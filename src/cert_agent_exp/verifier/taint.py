"""Taint check: n-gram overlap and/or embedding similarity with known payloads."""

from typing import Any


def ngram_overlap_ratio(text: str, payload_ngrams: set[tuple[str, ...]], n: int = 5) -> float:
    words = text.split()
    if len(words) < n:
        return 0.0
    count = 0
    for i in range(len(words) - n + 1):
        ng = tuple(words[i : i + n])
        if ng in payload_ngrams:
            count += 1
    return count / max(1, len(words) - n + 1)


def is_tainted(
    text: str,
    payload_ngrams: set[tuple[str, ...]],
    ngram_threshold: float = 0.02,
    embed_sim: float = 0.0,
    embed_threshold: float = 0.86,
) -> bool:
    ratio = ngram_overlap_ratio(text, payload_ngrams, n=5)
    if ratio >= ngram_threshold:
        return True
    if embed_sim >= embed_threshold:
        return True
    return False
