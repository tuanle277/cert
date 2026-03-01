"""Build chunked corpus and FAISS index. Deterministic chunk_id = doc_id + chunk_index."""

import argparse
import hashlib
import json
import os
import yaml
from tqdm import tqdm

from cert_agent_exp.common.io import ensure_dir, read_jsonl, write_jsonl
from cert_agent_exp.common.hashing import normalize_text
from cert_agent_exp.datasets import get_iterator
from cert_agent_exp.corpus import chunk_text, Embedder, FaissFlatIPIndex


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--max_docs", type=int, default=None, help="Max documents per dataset (light run; default: all)")
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config, "r"))
    data_dir = cfg["data_dir"]
    raw_dir = os.path.join(data_dir, "raw")
    corpus_dir = os.path.join(data_dir, "corpus")
    index_dir = os.path.join(data_dir, "indexes")
    ensure_dir(corpus_dir)
    ensure_dir(index_dir)

    corpus_cfg = cfg.get("corpus", {})
    chunk_tokens = int(corpus_cfg.get("chunk_tokens", 450))
    chunk_overlap = int(corpus_cfg.get("chunk_overlap", 60))
    embed_model = corpus_cfg.get("embed_model", "sentence-transformers/all-MiniLM-L6-v2")
    index_type = corpus_cfg.get("index_type", "faiss_flatip")

    chunks = []
    chunk_ids = []
    doc_ids = []
    for ds in cfg["datasets"]:
        name = ds["name"]
        path = os.path.join(raw_dir, f"{name}-train.jsonl")
        if not os.path.exists(path):
            print(f"[skip] {path} not found")
            continue
        it = get_iterator(name, read_jsonl(path))
        doc_count = 0
        for doc in tqdm(it, desc=name):
            if args.max_docs is not None and doc_count >= args.max_docs:
                break
            doc_count += 1
            text = doc.get("context", "") or doc.get("question", "")
            text = normalize_text(text)
            doc_id = str(doc.get("id", "")) or f"{name}_{len(chunks)}"
            for chunk_index, (chunk, _s, _e) in enumerate(chunk_text(text, chunk_tokens=chunk_tokens, overlap=chunk_overlap)):
                cid = f"{doc_id}_{chunk_index}"
                chunks.append(chunk)
                chunk_ids.append(cid)
                doc_ids.append(doc_id)

    if not chunks:
        print("[warn] no chunks; run 00_download_datasets first")
        return

    # Write corpus JSONL (id, text, doc_id) for provenance
    corpus_path = os.path.join(corpus_dir, "chunks.jsonl")
    write_jsonl(corpus_path, [{"id": i, "text": t, "doc_id": d} for i, t, d in zip(chunk_ids, chunks, doc_ids)])
    print(f"[ok] wrote {len(chunks)} chunks -> {corpus_path}")

    chunks_hash = _file_sha256(corpus_path)

    # Corpus manifest: everything needed to reproduce
    dataset_spec = {
        "datasets": [{"name": d["name"], "hf_id": d.get("hf_id"), "split": d.get("split", "train"), "max_examples": d.get("max_examples")} for d in cfg["datasets"]],
    }
    corpus_manifest = {
        "dataset": dataset_spec,
        "chunk_tokens": chunk_tokens,
        "chunk_overlap": chunk_overlap,
        "tokenization": "word_approx",
        "embed_model": embed_model,
        "chunks_hash": chunks_hash,
        "num_chunks": len(chunks),
    }
    manifest_path = os.path.join(corpus_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(corpus_manifest, f, indent=2)
    print(f"[ok] manifest -> {manifest_path}")

    integrity_path = os.path.join(corpus_dir, "integrity.sha256")
    with open(integrity_path, "w", encoding="utf-8") as f:
        f.write(f"{chunks_hash}  chunks.jsonl\n")
    print(f"[ok] integrity -> {integrity_path}")

    # Embed and build index
    embedder = Embedder(embed_model)
    vectors = embedder.embed(chunks)
    index = FaissFlatIPIndex(vectors.shape[1])
    index.add(chunk_ids, vectors)
    index_path = os.path.join(index_dir, "faiss_flatip.index")
    index.save(index_path)
    print(f"[ok] index -> {index_path}")

    index_manifest = {
        "index_type": index_type,
        "embed_model": embed_model,
        "chunks_hash": chunks_hash,
        "dim": int(vectors.shape[1]),
    }
    index_manifest_path = os.path.join(index_dir, "manifest.json")
    with open(index_manifest_path, "w", encoding="utf-8") as f:
        json.dump(index_manifest, f, indent=2)
    print(f"[ok] index manifest -> {index_manifest_path}")


if __name__ == "__main__":
    main()
