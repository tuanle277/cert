"""Deterministic token-based chunking. Use normalize_text() before chunking for stable span_hash."""

import re
from typing import Iterator


def tokenize_approx(text: str) -> list[str]:
    """Approximate word tokens (deterministic)."""
    return re.findall(r"\S+|\s+", text) if text else []


def chunk_text(
    text: str,
    chunk_tokens: int = 450,
    overlap: int = 60,
) -> Iterator[tuple[str, int, int]]:
    """Yield (chunk_text, start_idx, end_idx). Use normalized text for stable chunk boundaries."""
    tokens = tokenize_approx(text)
    step = max(1, chunk_tokens - overlap)
    for i in range(0, len(tokens), step):
        window = tokens[i : i + chunk_tokens]
        if not window:
            break
        chunk = "".join(window)
        yield chunk, i, i + len(window)
