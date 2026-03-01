"""Show visually what an attack looks like: input (original vs injected chunk) and output (agent response with clean vs injected retrieval)."""

import argparse
import json
import os
import yaml


def _truncate(s: str, max_chars: int = 400) -> str:
    s = s.strip()
    if not s:
        return s
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 3].rsplit(" ", 1)[0] + " ..."


def _tail(s: str, max_chars: int = 400) -> str:
    s = s.strip()
    if not s:
        return s
    if len(s) <= max_chars:
        return s
    return "... " + s[-max_chars:]


def _wrap(s: str, width: int = 72) -> str:
    out = []
    for i in range(0, len(s), width):
        out.append(s[i : i + width])
    return "\n".join(out)


def _extract_payload(orig: str, inj: str) -> str:
    """Get the added part (payload). Injection is usually orig + sep + payload (suffix) or payload + sep + orig (prefix)."""
    orig = orig.strip()
    inj = inj.strip()
    if not orig:
        return inj
    if inj.startswith(orig):
        added = inj[len(orig):].lstrip("\n ")
        return added
    if inj.endswith(orig):
        added = inj[:-len(orig)].rstrip("\n ")
        return added
    # Middle: find overlap
    for i in range(min(len(orig), len(inj)), 0, -1):
        if orig.endswith(inj[:i]):
            return inj[i:].lstrip("\n ")
        if inj.endswith(orig[:i]):
            return inj[:-i].rstrip("\n ")
    return ""


def _load_retriever(data_dir: str, chunk_jsonl_path: str, datasets_config_path: str):
    """Build retriever with index + chunk store from given chunks file."""
    try:
        from cert_agent_exp.common.io import read_jsonl
        from cert_agent_exp.corpus import FaissFlatIPIndex, Embedder, CorpusRetriever
    except Exception:
        return None
    index_path = os.path.join(data_dir, "indexes", "faiss_flatip.index")
    if not os.path.exists(index_path) or not os.path.exists(chunk_jsonl_path):
        return None
    with open(os.path.join(data_dir, "indexes", "manifest.json"), "r") as f:
        dim = json.load(f).get("dim", 384)
    index = FaissFlatIPIndex(dim)
    index.load(index_path)
    chunk_store = {r["id"]: r.get("text", "") for r in read_jsonl(chunk_jsonl_path)}
    embed_model = "sentence-transformers/all-MiniLM-L6-v2"
    if datasets_config_path and os.path.exists(datasets_config_path):
        with open(datasets_config_path, "r") as f:
            embed_model = yaml.safe_load(f).get("corpus", {}).get("embed_model", embed_model)
    embedder = Embedder(embed_model)
    return CorpusRetriever(index, embedder, chunk_store)


def _run_output_comparison(data_dir: str, config_path: str, base_dir: str):
    """Run same task with clean vs injected retrieval; return {clean: {...}, injected: {...}} or None."""
    try:
        from cert_agent_exp.common.io import read_jsonl
        from cert_agent_exp.agent import run_episode
        from cert_agent_exp.tools import SearchTool, ReadDocTool
    except Exception:
        return None
    tasks_path = os.path.join(data_dir, "tasks", "hotpotqa_tasks.jsonl")
    if not os.path.exists(tasks_path):
        return None
    task = next(iter(read_jsonl(tasks_path)), None)
    if not task:
        return None
    cfg = yaml.safe_load(open(config_path, "r"))
    ds_cfg_path = os.path.join(base_dir, "datasets.yaml")
    clean_path = os.path.join(data_dir, "corpus", "chunks.jsonl")
    inj_path = os.path.join(data_dir, "corpus_injected", "chunks_injected.jsonl")
    retriever_clean = _load_retriever(data_dir, clean_path, ds_cfg_path)
    retriever_inj = _load_retriever(data_dir, inj_path, ds_cfg_path)
    if retriever_clean is None or retriever_inj is None:
        return None
    tools_clean = [SearchTool(retriever=retriever_clean, retrieval_mode="faiss"), ReadDocTool()]
    tools_inj = [SearchTool(retriever=retriever_inj, retrieval_mode="faiss"), ReadDocTool()]
    out_clean = run_episode(task, tools_clean, agent_type="retrieval_echo", max_steps=12)
    out_inj = run_episode(task, tools_inj, agent_type="retrieval_echo", max_steps=12)
    return {"clean": out_clean, "injected": out_inj}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/grid.yaml")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--max-examples", type=int, default=2, help="Number of chunk pairs to show")
    ap.add_argument("--with-output-compare", action="store_true", default=True, help="Run agent with clean vs injected retrieval and show output difference (default: True)")
    ap.add_argument("--no-output-compare", action="store_true", help="Skip output comparison (avoids loading embedder)")
    args = ap.parse_args()
    if args.no_output_compare:
        args.with_output_compare = False

    cfg = yaml.safe_load(open(args.config, "r"))
    data_dir = cfg["data_dir"]
    runs_dir = cfg.get("runs_dir", "runs")
    out_dir = args.out_dir or os.path.join(runs_dir, "figures")
    os.makedirs(out_dir, exist_ok=True)

    corpus_path = os.path.join(data_dir, "corpus", "chunks.jsonl")
    injected_path = os.path.join(data_dir, "corpus_injected", "chunks_injected.jsonl")
    manifest_path = os.path.join(data_dir, "corpus_injected", "injection_manifest.json")
    if not os.path.exists(corpus_path) or not os.path.exists(injected_path):
        print("[err] run 01_build_corpus and 03_inject_corpus first")
        return

    from cert_agent_exp.common.io import read_jsonl

    orig_by_id = {r["id"]: r.get("text", "") for r in read_jsonl(corpus_path)}
    inj_by_id = {r["id"]: r.get("text", "") for r in read_jsonl(injected_path)}

    injected_ids = list(inj_by_id.keys())
    placement_by_id = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        injected_ids = [e["chunk_id"] for e in manifest.get("injections", [])[: args.max_examples]]
        for e in manifest.get("injections", []):
            placement_by_id[e["chunk_id"]] = e.get("placement", "suffix")
    if not injected_ids:
        injected_ids = list(inj_by_id.keys())[: args.max_examples]

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib required for figure")
        return

    for idx, chunk_id in enumerate(injected_ids):
        if chunk_id not in orig_by_id or chunk_id not in inj_by_id:
            continue
        orig = orig_by_id[chunk_id]
        inj = inj_by_id[chunk_id]
        payload = _extract_payload(orig, inj)
        placement = placement_by_id.get(chunk_id, "suffix")

        # Top: original (start). Bottom: injected = same start + PAYLOAD CALLOUT + payload
        orig_show = _truncate(orig, 380)
        if payload:
            inj_show = _truncate(orig, 120) + "\n\n  ═══ INJECTED PAYLOAD (attacker-added) ═══\n  " + _wrap(payload, 70).replace("\n", "\n  ") + "\n  ═══════════════════════════════════════"
        else:
            inj_show = _truncate(inj, 500)

        fig, axes = plt.subplots(2, 1, figsize=(10, 6))
        fig.suptitle(f"Chunk: {chunk_id[:24]}...  (placement: {placement})", fontsize=12)
        axes[0].set_title("Original chunk (clean) — first 380 chars", fontsize=10)
        axes[0].text(0.02, 0.98, _wrap(orig_show), transform=axes[0].transAxes, fontsize=7, verticalalignment="top", family="monospace")
        axes[0].set_xlim(0, 1)
        axes[0].set_ylim(0, 1)
        axes[0].axis("off")
        axes[1].set_title("After injection — same start, then PAYLOAD appended", fontsize=10)
        axes[1].text(0.02, 0.98, _wrap(inj_show), transform=axes[1].transAxes, fontsize=7, verticalalignment="top", family="monospace")
        axes[1].set_xlim(0, 1)
        axes[1].set_ylim(0, 1)
        axes[1].axis("off")
        plt.tight_layout()
        out_path = os.path.join(out_dir, f"attack_example_{idx + 1}.png")
        fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close()
        print(f"[ok] {out_path}")

    # Combined: left = original start, right = PAYLOAD only (so the difference is obvious)
    if injected_ids:
        chunk_id = injected_ids[0]
        orig = orig_by_id.get(chunk_id, "")
        inj = inj_by_id.get(chunk_id, "")
        payload = _extract_payload(orig, inj)
        fig, (ax0, ax1) = plt.subplots(1, 2, figsize=(12, 5))
        fig.suptitle("What the attack looks like inside the pipeline", fontsize=12)
        ax0.set_title("Original chunk (clean)", fontsize=11)
        ax0.text(0.02, 0.98, _wrap(_truncate(orig, 450)), transform=ax0.transAxes, fontsize=7, va="top", family="monospace")
        ax0.axis("off")
        ax1.set_title("What was ADDED (injected payload) — this is what the model also sees", fontsize=11)
        if payload:
            ax1.text(0.02, 0.98, _wrap(payload), transform=ax1.transAxes, fontsize=8, va="top", family="monospace",
                     bbox=dict(boxstyle="round", facecolor="mistyrose", alpha=0.9))
        else:
            ax1.text(0.5, 0.5, "Could not extract payload (chunk may be identical?).", ha="center", va="center")
        ax1.axis("off")
        plt.tight_layout()
        combined_path = os.path.join(out_dir, "attack_inside_pipeline.png")
        fig.savefig(combined_path, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close()
        print(f"[ok] {combined_path}")

    # Output comparison: same task, clean vs injected retrieval → show difference in agent output
    output_comparison = None
    if args.with_output_compare:
        base_dir = os.path.dirname(args.config)
        output_comparison = _run_output_comparison(data_dir, args.config, base_dir)
    if output_comparison:
        c = output_comparison["clean"]
        i = output_comparison["injected"]
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            fig, (ax0, ax1) = plt.subplots(1, 2, figsize=(11, 5))
            fig.suptitle("Output difference: same task, clean vs injected retrieval", fontsize=12)
            ax0.set_title("Agent output (clean corpus)", fontsize=11)
            ax0.text(0.02, 0.98, _wrap(c.get("final_answer", "") or "(none)"), transform=ax0.transAxes, fontsize=8, va="top", family="monospace",
                     bbox=dict(boxstyle="round", facecolor="honeydew", alpha=0.9))
            ax0.axis("off")
            ax1.set_title("Agent output (injected corpus)", fontsize=11)
            ax1.text(0.02, 0.98, _wrap(i.get("final_answer", "") or "(none)"), transform=ax1.transAxes, fontsize=8, va="top", family="monospace",
                     bbox=dict(boxstyle="round", facecolor="mistyrose", alpha=0.9))
            ax1.axis("off")
            plt.tight_layout()
            out_compare_path = os.path.join(out_dir, "attack_output_comparison.png")
            fig.savefig(out_compare_path, dpi=150, bbox_inches="tight", facecolor="white")
            plt.close()
            print(f"[ok] output comparison -> {out_compare_path}")
        except Exception as e:
            print(f"[skip] output comparison figure: {e}")

    # Text file: input diff + output diff
    txt_path = os.path.join(out_dir, "attack_example_snippets.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=== What the attack looks like (original vs injected) ===\n\n")
        for cid in injected_ids[:3]:
            orig = orig_by_id.get(cid, "")
            inj = inj_by_id.get(cid, "")
            payload = _extract_payload(orig, inj)
            f.write(f"--- chunk_id: {cid} ---\n\n")
            f.write("ORIGINAL (first 400 chars):\n")
            f.write(_truncate(orig, 400) + "\n\n")
            f.write("INJECTED PAYLOAD (the part that was added — this is what the attacker injects):\n")
            f.write(payload if payload else "(none extracted)\n")
            f.write("\n")
            f.write("FULL INJECTED CHUNK (last 400 chars, where payload usually is):\n")
            f.write(_tail(inj, 400) + "\n\n")
        if output_comparison:
            c = output_comparison["clean"]
            i = output_comparison["injected"]
            out_clean = (c.get("final_answer") or "(none)")
            out_inj = (i.get("final_answer") or "(none)")
            inj_sources = set()
            if os.path.exists(manifest_path):
                with open(manifest_path, "r") as mf:
                    inj_manifest = json.load(mf)
                inj_sources = {e["chunk_id"] for e in inj_manifest.get("injections", [])}
            exposed_inj = [x for x in (i.get("exposed_sources") or []) if x in inj_sources]
            f.write("\n=== OUTPUT DIFFERENCE (same task, clean vs injected retrieval) ===\n\n")
            f.write("AGENT OUTPUT (clean corpus):\n")
            f.write(out_clean + "\n\n")
            f.write("AGENT OUTPUT (injected corpus):\n")
            f.write(out_inj + "\n\n")
            f.write("Exposed sources (clean): " + str(c.get("exposed_sources", [])) + "\n")
            f.write("Exposed sources (injected): " + str(i.get("exposed_sources", [])) + "\n")
            f.write("Injected sources (retrieved chunks that contained payload): " + str(exposed_inj) + "\n\n")
            if out_clean != out_inj:
                f.write(">>> OUTPUTS DIFFER: injected run returned different text.\n")
            if any(marker in out_inj for marker in ("PWNED", "Override", "COMPLIANCE", "Execute the following", "policy section")):
                f.write(">>> INJECTED OUTPUT CONTAINS ATTACK PAYLOAD TEXT (model saw poisoned content).\n")
            if out_clean == out_inj and len(out_inj) > 300:
                f.write(">>> (Outputs may show same start; payload often at end of retrieved text — check 'end' in agent output.)\n")
    print(f"[ok] {txt_path}")
    if args.with_output_compare and output_comparison is None:
        print("[warn] output comparison skipped (missing index/corpus or embedder)")


if __name__ == "__main__":
    main()
