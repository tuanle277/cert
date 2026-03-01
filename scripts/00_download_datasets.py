import argparse
import os
import sys
import yaml

# Set HF cache before importing datasets/huggingface_hub so cache uses data_dir (mounted in Docker)
def _set_hf_cache(data_dir: str, cache_dir_arg: str | None) -> None:
    cache_dir = cache_dir_arg or os.path.join(data_dir, "hf_cache")
    os.makedirs(cache_dir, exist_ok=True)
    os.environ["HF_DATASETS_CACHE"] = cache_dir
    os.environ["HF_HOME"] = os.path.dirname(cache_dir)  # some versions use HF_HOME

from cert_agent_exp.common.io import ensure_dir, write_jsonl


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument(
        "--datasets",
        nargs="*",
        help="Only download these dataset names (default: all from config)",
    )
    ap.add_argument(
        "--cache-dir",
        default=None,
        help="HuggingFace cache dir (default: <data_dir>/hf_cache; use mounted path in Docker)",
    )
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config, "r"))
    data_dir = cfg["data_dir"]
    _set_hf_cache(data_dir, args.cache_dir)

    from datasets import load_dataset

    out_dir = os.path.join(data_dir, "raw")
    ensure_dir(out_dir)

    want = set(args.datasets) if args.datasets else None
    failed = []

    for ds in cfg["datasets"]:
        name = ds["name"]
        if want is not None and name not in want:
            continue
        hf_id = ds["hf_id"]
        subset = ds.get("subset")
        split = ds.get("split", "train")
        max_n = int(ds.get("max_examples", 1000))

        try:
            dset = load_dataset(hf_id, subset, split=split)
            dset = dset.select(range(min(max_n, len(dset))))
            out_path = os.path.join(out_dir, f"{name}-{split}.jsonl")
            write_jsonl(out_path, dset)
            print(f"[ok] wrote {len(dset)} rows -> {out_path}")
        except Exception as e:
            print(f"[skip] {name}: {e}", file=sys.stderr)
            failed.append(name)

    if failed:
        print(f"[warn] failed: {failed}; remaining datasets were written", file=sys.stderr)
