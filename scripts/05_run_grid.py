"""Run full grid. Uses injected corpus for retrieval so attacks happen every run. Logs exposed_sources, etc."""

import argparse
import hashlib
import json
import os
import yaml
from tqdm import tqdm

from cert_agent_exp.common.io import ensure_dir, read_jsonl, write_jsonl
from cert_agent_exp.agent import run_episode
from cert_agent_exp.tools import SearchTool, ReadDocTool


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _benchmark_hashes(data_dir: str, grid: dict) -> dict[str, str]:
    """Compute hashes for frozen benchmark reproducibility. Logged per run when benchmark_id is set."""
    out = {}
    # Corpus: from manifest chunks_hash
    corpus_manifest_path = os.path.join(data_dir, "corpus", "manifest.json")
    if os.path.exists(corpus_manifest_path):
        with open(corpus_manifest_path, "r", encoding="utf-8") as f:
            m = json.load(f)
        out["benchmark_corpus_hash"] = m.get("chunks_hash", "")[:16]
        ds_spec = m.get("dataset", {})
        out["benchmark_dataset_hash"] = hashlib.sha256(json.dumps(ds_spec, sort_keys=True).encode()).hexdigest()[:16]
    else:
        out["benchmark_corpus_hash"] = ""
        out["benchmark_dataset_hash"] = ""
    # Tasks: hash of task file (or first N tasks)
    datasets = grid.get("datasets", ["hotpotqa"])
    for ds_name in datasets:
        tasks_path = os.path.join(data_dir, "tasks", f"{ds_name}_tasks.jsonl")
        if os.path.exists(tasks_path):
            out["benchmark_task_hash"] = _file_sha256(tasks_path)[:16]
            break
    else:
        out["benchmark_task_hash"] = ""
    # Attack: hash of injection manifest
    inj_path = os.path.join(data_dir, "corpus_injected", "injection_manifest.json")
    if os.path.exists(inj_path):
        out["benchmark_attack_hash"] = _file_sha256(inj_path)[:16]
    else:
        out["benchmark_attack_hash"] = ""
    return out


def _load_retriever_with_injected_corpus(data_dir: str, datasets_config_path: str):
    """Build retriever that serves from corpus_injected so every search returns (possibly) poisoned chunks."""
    try:
        from cert_agent_exp.corpus import FaissFlatIPIndex, Embedder, CorpusRetriever
    except Exception:
        return None
    index_path = os.path.join(data_dir, "indexes", "faiss_flatip.index")
    injected_path = os.path.join(data_dir, "corpus_injected", "chunks_injected.jsonl")
    if not os.path.exists(index_path) or not os.path.exists(injected_path):
        return None
    # Load index (need dim from manifest or from first load)
    index_manifest_path = os.path.join(data_dir, "indexes", "manifest.json")
    if os.path.exists(index_manifest_path):
        with open(index_manifest_path, "r") as f:
            manifest = json.load(f)
            dim = manifest.get("dim", 384)
    else:
        dim = 384
    index = FaissFlatIPIndex(dim)
    index.load(index_path)
    chunk_store = {}
    for row in read_jsonl(injected_path):
        chunk_store[row["id"]] = row.get("text", "")
    embed_model = "sentence-transformers/all-MiniLM-L6-v2"
    if datasets_config_path and os.path.exists(datasets_config_path):
        ds_cfg = yaml.safe_load(open(datasets_config_path, "r"))
        embed_model = ds_cfg.get("corpus", {}).get("embed_model", embed_model)
    embedder = Embedder(embed_model)
    return CorpusRetriever(index, embedder, chunk_store)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--datasets-config", default=None, help="Path to datasets.yaml for embed_model (default: configs/datasets.yaml)")
    ap.add_argument("--max_per_cell", type=int, default=2, help="Max runs per grid cell (default 2 for light run)")
    ap.add_argument("--light", action="store_true", help="Minimal grid: 1 task, 1 defense, 1 seed (easy on laptop)")
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config, "r"))
    data_dir = cfg["data_dir"]
    runs_dir = cfg.get("runs_dir", "runs")
    retrieval_mode = cfg.get("retrieval_mode", "faiss")
    use_injected_corpus = cfg.get("use_injected_corpus", True)
    benchmark_id = cfg.get("benchmark_id", "")
    grid = cfg.get("grid", {})
    if args.light:
        grid = {**grid, "defenses": grid.get("defenses", ["none"])[:1], "seeds": [0]}
        args.max_per_cell = 1
    max_tasks = grid.get("max_tasks")  # optional cap (e.g. benchmark_v1: 100)
    max_per_cell_from_grid = grid.get("max_per_cell")  # benchmark can set e.g. 100
    agent_cfg = cfg.get("agent", {})
    model_cfg = cfg.get("models", {})

    log_dir = os.path.join(runs_dir, "logs")
    ensure_dir(log_dir)

    benchmark_hashes = {}
    if benchmark_id:
        benchmark_hashes = _benchmark_hashes(data_dir, grid)
        print(f"[grid] benchmark_id={benchmark_id} hashes: corpus={benchmark_hashes.get('benchmark_corpus_hash', '')} task={benchmark_hashes.get('benchmark_task_hash', '')} attack={benchmark_hashes.get('benchmark_attack_hash', '')}")

    # Load injection manifest to mark which exposed_sources were injected
    injected_chunk_ids = set()
    inj_manifest_path = os.path.join(data_dir, "corpus_injected", "injection_manifest.json")
    if os.path.exists(inj_manifest_path):
        with open(inj_manifest_path, "r", encoding="utf-8") as f:
            inj = json.load(f)
            for entry in inj.get("injections", []):
                injected_chunk_ids.add(entry.get("chunk_id", ""))

    datasets = grid.get("datasets", ["hotpotqa"])
    defenses = grid.get("defenses", ["none"])
    seeds = grid.get("seeds", [0])

    retriever = None
    if use_injected_corpus and retrieval_mode == "faiss":
        base = os.path.dirname(args.config)
        ds_cfg_path = args.datasets_config or os.path.join(base, "datasets.yaml")
        retriever = _load_retriever_with_injected_corpus(data_dir, ds_cfg_path)
        if retriever is not None:
            print("[grid] using injected corpus for retrieval (attack on every run)")
        else:
            print("[grid] injected retriever not available; using mock search")

    tools = [
        SearchTool(retriever=retriever, retrieval_mode=retrieval_mode),
        ReadDocTool(),
    ]
    all_logs = []
    for ds_name in datasets:
        tasks_path = os.path.join(data_dir, "tasks", f"{ds_name}_tasks.jsonl")
        if not os.path.exists(tasks_path):
            print(f"[skip] {tasks_path} not found")
            continue
        tasks = list(read_jsonl(tasks_path))
        cap = min(max_tasks, len(tasks)) if max_tasks is not None else len(tasks)
        if args.light:
            effective_max = args.max_per_cell  # light overrides grid
        else:
            effective_max = max_per_cell_from_grid if max_per_cell_from_grid is not None else args.max_per_cell
        cap = min(cap, effective_max) if effective_max else cap
        tasks = tasks[:cap]
        for defense in defenses:
            for seed in seeds:
                for task in tqdm(tasks, desc=f"{ds_name}_{defense}_s{seed}"):
                    result = run_episode(
                        task,
                        tools,
                        agent_type=agent_cfg.get("type", "react"),
                        max_steps=agent_cfg.get("max_steps", 12),
                        model_mode=model_cfg.get("mode", "mock"),
                    )
                    result["dataset"] = ds_name
                    result["defense"] = defense
                    result["seed"] = seed
                    result["retrieval_mode"] = retrieval_mode
                    result["use_injected_corpus"] = use_injected_corpus
                    result["injected_sources"] = [s for s in result.get("exposed_sources", []) if s in injected_chunk_ids]
                    result["task"] = task  # for is_bad_action and metrics
                    if benchmark_id:
                        result["benchmark_id"] = benchmark_id
                        result.update(benchmark_hashes)
                    all_logs.append(result)

    log_path = os.path.join(log_dir, "grid_run.jsonl")
    write_jsonl(log_path, all_logs)
    print(f"[ok] wrote {len(all_logs)} run logs -> {log_path}")


if __name__ == "__main__":
    main()
