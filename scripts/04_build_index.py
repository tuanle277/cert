"""Step 4: Build FAISS index over the (possibly injected) corpus.

Embeds all chunks using sentence-transformers and builds a flat
inner-product index for retrieval.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from cert_agent_exp.common.io import ensure_dir, read_jsonl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="data/corpus_injected/chunks_injected.jsonl",
                    help="Path to corpus JSONL (clean or injected)")
    ap.add_argument("--output-dir", default="data/indexes")
    ap.add_argument("--config", default="configs/datasets.yaml")
    ap.add_argument("--batch-size", type=int, default=64)
    args = ap.parse_args()

    import yaml
    cfg = yaml.safe_load(open(args.config)) if os.path.exists(args.config) else {}
    embed_model = cfg.get("corpus", {}).get("embed_model",
                                             "sentence-transformers/all-MiniLM-L6-v2")

    ensure_dir(args.output_dir)

    if not os.path.exists(args.corpus):
        print(f"[error] Corpus not found: {args.corpus}")
        print("  Run 02_build_corpus.py and 03_inject_corpus.py first.")
        return

    chunks = read_jsonl(args.corpus)
    texts = [c["text"] for c in chunks]
    ids = [c["id"] for c in chunks]
    print(f"[info] Embedding {len(chunks)} chunks with {embed_model}")

    from cert_agent_exp.corpus import Embedder, FaissFlatIPIndex

    embedder = Embedder(embed_model)
    vectors = embedder.encode(texts, batch_size=args.batch_size)
    dim = vectors.shape[1]

    index = FaissFlatIPIndex(dim)
    index.add(vectors)

    index_path = os.path.join(args.output_dir, "faiss_flatip.index")
    index.save(index_path)

    manifest = {
        "num_vectors": index.ntotal,
        "dim": dim,
        "embed_model": embed_model,
        "corpus_path": args.corpus,
        "chunk_ids": ids,
    }
    manifest_path = os.path.join(args.output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[ok] Index ({index.ntotal} vectors, dim={dim}) -> {index_path}")
    print(f"[ok] Manifest -> {manifest_path}")


if __name__ == "__main__":
    main()
