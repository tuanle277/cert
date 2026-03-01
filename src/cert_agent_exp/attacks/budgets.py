"""Injection budgets: B_tokens (payload size), K_sources (number of sources)."""

from typing import Any


def apply_budget(payload: str, B_tokens: int) -> str:
    """Truncate or pad payload to at most B_tokens (approximate word count)."""
    tokens = payload.split()
    if len(tokens) <= B_tokens:
        return payload
    return " ".join(tokens[:B_tokens])
