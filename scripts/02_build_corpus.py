"""Step 2: Build document corpus from HotpotQA task contexts.

Reads the prepared tasks, extracts context paragraphs as chunks,
deduplicates, and writes a corpus JSONL + manifest.
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from cert_agent_exp.common.io import ensure_dir, read_jsonl, write_jsonl


def _chunk_id(title: str, sent_idx: int) -> str:
    h = hashlib.md5(title.encode()).hexdigest()[:12]
    return f"{h}_{sent_idx}"


def extract_chunks(tasks: list[dict]) -> list[dict]:
    seen: set[str] = set()
    chunks: list[dict] = []

    for task in tasks:
        titles = task.get("context_titles", [])
        sentences_list = task.get("context_sentences", [])

        for title, sents in zip(titles, sentences_list):
            text = " ".join(sents).strip()
            if not text:
                continue
            cid = _chunk_id(title, 0)
            if cid in seen:
                continue
            seen.add(cid)
            chunks.append({
                "id": cid,
                "title": title,
                "text": text,
                "source": "hotpotqa",
            })

    return chunks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", default="data/tasks/hotpotqa_tasks.jsonl")
    ap.add_argument("--output-dir", default="data/corpus")
    args = ap.parse_args()

    ensure_dir(args.output_dir)

    if os.path.exists(args.tasks):
        tasks = read_jsonl(args.tasks)
    else:
        print(f"[warn] {args.tasks} not found, creating minimal corpus")
        tasks = []

    chunks = extract_chunks(tasks)

    if not chunks:
        chunks = [
            {"id": "fallback_0", "title": "Arthur's Magazine",
             "text": "Arthur's Magazine (1844-1846) was an American literary periodical published in Philadelphia.",
             "source": "synthetic"},
            {"id": "fallback_1", "title": "First for Women",
             "text": "First for Women is a woman's magazine published by Bauer Media Group, started in 1989.",
             "source": "synthetic"},
            {"id": "fallback_2", "title": "Radio City",
             "text": "Radio City is India's first private FM radio station, started on 3 July 2001.",
             "source": "synthetic"},
        ]

    chunks_path = os.path.join(args.output_dir, "chunks.jsonl")
    write_jsonl(chunks_path, chunks)

    corpus_hash = hashlib.sha256(
        json.dumps([c["id"] for c in chunks], sort_keys=True).encode()
    ).hexdigest()[:16]

    manifest = {
        "num_chunks": len(chunks),
        "chunks_hash": corpus_hash,
        "dataset": {"name": "hotpotqa", "split": "validation"},
    }
    manifest_path = os.path.join(args.output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[ok] Wrote {len(chunks)} chunks -> {chunks_path}")
    print(f"[ok] Manifest -> {manifest_path}")


if __name__ == "__main__":
    main()
