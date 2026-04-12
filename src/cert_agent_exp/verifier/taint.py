"""Taint check: n-gram overlap with known attack payloads, augmented by
cosine similarity of sentence embeddings for paraphrase robustness.

Strategy: build n-grams at multiple sizes from the payload (sizes 2..max_n).
When checking text, compute overlap at each size and take the maximum ratio.
This handles both short payloads ("PWNED") and long ones.

The embedding augmentation computes cosine similarity between the text and
the raw payload using sentence-transformers, catching paraphrased attacks
that n-gram overlap alone would miss.

The `taint_detail()` function produces a full diagnostic object containing
matched n-grams, their positions, source attribution, and embedding
similarity — the internal proof that the verifier is blocking for the right
reason.
"""

import re
from typing import Any

import numpy as np

_PUNCT_RE = re.compile(r"[^\w\s]")

# ── Embedding cache (lazy-loaded) ───────────────────────────────────────────

_embed_model = None
_embed_cache: dict[str, np.ndarray] = {}


def _get_embedder():
    global _embed_model
    if _embed_model is not None:
        return _embed_model
    try:
        from sentence_transformers import SentenceTransformer
        _embed_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    except ImportError:
        _embed_model = None
    return _embed_model


def _embed_text(text: str) -> np.ndarray | None:
    """Embed text using sentence-transformers (cached)."""
    if not text:
        return None
    key = text[:500]
    if key in _embed_cache:
        return _embed_cache[key]
    model = _get_embedder()
    if model is None:
        return None
    vec = model.encode([text], show_progress_bar=False)[0]
    _embed_cache[key] = vec
    return vec


def compute_embedding_similarity(text: str, payload_text: str) -> float:
    """Cosine similarity between text and payload embeddings.

    Returns 0.0 if sentence-transformers is not available.
    """
    vec_a = _embed_text(text)
    vec_b = _embed_text(payload_text)
    if vec_a is None or vec_b is None:
        return 0.0
    dot = float(np.dot(vec_a, vec_b))
    norm = float(np.linalg.norm(vec_a) * np.linalg.norm(vec_b))
    if norm < 1e-9:
        return 0.0
    return dot / norm


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
    raw_payload_text: str = "",
    embed_threshold: float = 0.86,
    use_embeddings: bool = True,
) -> dict[str, Any]:
    """Produce a full taint diagnostic object.

    Returns a dict with:
      tainted: bool
      ngram_score: float
      embed_similarity: float              — cosine similarity with payload embedding
      threshold: float
      embed_threshold: float
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

    ngram_tainted = best_ratio >= ngram_threshold

    embed_sim = 0.0
    embed_tainted = False
    if use_embeddings and raw_payload_text:
        embed_sim = compute_embedding_similarity(text, raw_payload_text)
        embed_tainted = embed_sim >= embed_threshold

    tainted = ngram_tainted or embed_tainted

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
            chunk_embed_sim = 0.0
            if use_embeddings and raw_payload_text:
                chunk_embed_sim = compute_embedding_similarity(ctext, raw_payload_text)
            is_taint = score >= ngram_threshold or chunk_embed_sim >= embed_threshold
            if score > 0 or chunk_embed_sim > 0.5:
                taint_sources.append({
                    "chunk_id": cid,
                    "ngram_score": round(score, 4),
                    "embed_similarity": round(chunk_embed_sim, 4),
                    "is_tainted": is_taint,
                })
        taint_sources.sort(key=lambda x: x["ngram_score"], reverse=True)

    taint_reason = "clean"
    if ngram_tainted and embed_tainted:
        taint_reason = "ngram+embedding"
    elif ngram_tainted:
        taint_reason = "ngram_overlap"
    elif embed_tainted:
        taint_reason = "embedding_similarity"

    return {
        "tainted": tainted,
        "taint_reason": taint_reason,
        "ngram_score": round(best_ratio, 6),
        "embed_similarity": round(embed_sim, 6),
        "best_ngram_size": best_n,
        "threshold": ngram_threshold,
        "embed_threshold": embed_threshold,
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
    raw_payload_text: str = "",
    use_embeddings: bool = True,
) -> bool:
    """True if text is tainted by the known payload (n-gram OR embedding)."""
    ratio = ngram_overlap_ratio(text, payload_ngrams)
    if ratio >= ngram_threshold:
        return True
    if embed_sim >= embed_threshold:
        return True
    if use_embeddings and raw_payload_text and embed_sim == 0.0:
        computed_sim = compute_embedding_similarity(text, raw_payload_text)
        if computed_sim >= embed_threshold:
            return True
    return False
