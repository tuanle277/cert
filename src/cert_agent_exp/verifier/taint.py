"""Taint check: n-gram overlap with known attack payloads.

Strategy: build n-grams at multiple sizes from the payload (sizes 2..max_n).
When checking text, compute overlap at each size and take the maximum ratio.
This handles both short payloads ("PWNED") and long ones.

The `taint_detail()` function produces a full diagnostic object containing
matched n-grams, their positions, and source attribution — the internal
proof that the verifier is blocking for the right reason.
"""

import re
from typing import Any

_PUNCT_RE = re.compile(r"[^\w\s]")


def _normalize_word(w: str) -> str:
    """Strip punctuation and lowercase for robust matching."""
    return _PUNCT_RE.sub("", w.lower())


def _normalize_words(text: str) -> list[str]:
    """Tokenize, lowercase, strip punctuation — 'PWNED..' and 'pwned.' both become 'pwned'."""
    return [_normalize_word(w) for w in text.split() if _normalize_word(w)]


def build_payload_ngrams(text: str, max_n: int = 5) -> set[tuple[str, ...]]:
    """Build normalized n-gram set from a payload at multiple sizes (2..max_n)."""
    words = _normalize_words(text)
    if not words:
        return set()
    ngrams: set[tuple[str, ...]] = set()
    min_n = min(2, len(words))
    for n in range(min_n, max_n + 1):
        if len(words) < n:
            continue
        for i in range(len(words) - n + 1):
            ngrams.add(tuple(words[i: i + n]))
    if not ngrams:
        ngrams.add(tuple(words))
    return ngrams


def _ngram_sizes_present(payload_ngrams: set[tuple[str, ...]]) -> list[int]:
    return sorted({len(ng) for ng in payload_ngrams})


def ngram_overlap_ratio(text: str, payload_ngrams: set[tuple[str, ...]], max_n: int = 5) -> float:
    """Compute max overlap ratio across all n-gram sizes present in payload_ngrams."""
    if not payload_ngrams:
        return 0.0
    words = _normalize_words(text)
    if not words:
        return 0.0
    sizes = _ngram_sizes_present(payload_ngrams)
    best_ratio = 0.0
    for n in sizes:
        if len(words) < n:
            continue
        total = len(words) - n + 1
        count = sum(1 for i in range(total) if tuple(words[i: i + n]) in payload_ngrams)
        ratio = count / max(1, total)
        best_ratio = max(best_ratio, ratio)
    return best_ratio


def taint_detail(
    text: str,
    payload_ngrams: set[tuple[str, ...]],
    ngram_threshold: float = 0.02,
    chunk_texts: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Produce a full taint diagnostic object.

    Returns a dict with:
      tainted: bool
      ngram_score: float
      threshold: float
      matched_ngrams: list[str]           — human-readable matched n-grams
      matched_positions: list[int]         — word-offset positions in text
      tainted_spans: list[str]             — exact substrings of text that overlapped
      taint_sources: list[dict]            — which chunks caused the taint (with per-chunk scores)
    """
    words = _normalize_words(text)
    raw_words = text.split()
    sizes = _ngram_sizes_present(payload_ngrams) if payload_ngrams else []
    best_ratio = 0.0
    best_n = 0
    all_matched: list[tuple[int, int, tuple[str, ...]]] = []

    for n in sizes:
        if len(words) < n:
            continue
        total = len(words) - n + 1
        count = 0
        for i in range(total):
            ng = tuple(words[i: i + n])
            if ng in payload_ngrams:
                count += 1
                all_matched.append((i, n, ng))
        ratio = count / max(1, total)
        if ratio > best_ratio:
            best_ratio = ratio
            best_n = n

    tainted = best_ratio >= ngram_threshold

    matched_ngrams = sorted({" ".join(ng) for _, _, ng in all_matched})

    matched_positions = sorted({pos for pos, _, _ in all_matched})

    tainted_spans = []
    for pos, n, _ in all_matched:
        end = min(pos + n, len(raw_words))
        span = " ".join(raw_words[pos:end])
        if span not in tainted_spans:
            tainted_spans.append(span)
    tainted_spans = tainted_spans[:20]

    taint_sources: list[dict[str, Any]] = []
    if chunk_texts:
        for cid, ctext in chunk_texts.items():
            score = ngram_overlap_ratio(ctext, payload_ngrams)
            if score > 0:
                taint_sources.append({
                    "chunk_id": cid,
                    "ngram_score": round(score, 4),
                    "is_tainted": score >= ngram_threshold,
                })
        taint_sources.sort(key=lambda x: x["ngram_score"], reverse=True)

    return {
        "tainted": tainted,
        "ngram_score": round(best_ratio, 6),
        "best_ngram_size": best_n,
        "threshold": ngram_threshold,
        "num_matched_ngrams": len(all_matched),
        "matched_ngrams": matched_ngrams[:15],
        "matched_positions": matched_positions[:20],
        "tainted_spans": tainted_spans,
        "taint_sources": taint_sources[:10],
    }


def is_tainted(
    text: str,
    payload_ngrams: set[tuple[str, ...]],
    ngram_threshold: float = 0.02,
    embed_sim: float = 0.0,
    embed_threshold: float = 0.86,
) -> bool:
    """True if text is tainted by the known payload."""
    ratio = ngram_overlap_ratio(text, payload_ngrams)
    if ratio >= ngram_threshold:
        return True
    if embed_sim >= embed_threshold:
        return True
    return False
