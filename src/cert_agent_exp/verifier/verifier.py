"""Verifier: check tool output / agent action against certificates and taint."""

from typing import Any

from .certificate import make_certificate
from .taint import is_tainted


def verify(
    content: str,
    certificates: list[dict[str, Any]],
    payload_ngrams: set[tuple[str, ...]],
    config: dict[str, Any],
) -> tuple[bool, str]:
    """Returns (allowed, reason)."""
    taint_cfg = config.get("taint", {})
    if is_tainted(
        content,
        payload_ngrams,
        ngram_threshold=taint_cfg.get("ngram_overlap_threshold", 0.02),
        embed_sim=0.0,
        embed_threshold=taint_cfg.get("embed_similarity_threshold", 0.86),
    ):
        return False, "tainted"
    return True, "ok"
