"""Verifier: check agent action against certificates and taint.

Returns (allowed, reason, debug) where debug is a structured diagnostic object
that constitutes the internal proof of why the action was allowed or rejected.
"""

from typing import Any

from .certificate import make_certificate
from .taint import is_tainted, taint_detail, ngram_overlap_ratio


def verify(
    content: str,
    certificates: list[dict[str, Any]],
    payload_ngrams: set[tuple[str, ...]],
    config: dict[str, Any],
    chunk_texts: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Returns (allowed, reason). Legacy 2-tuple interface."""
    allowed, reason, _ = verify_with_debug(
        content, certificates, payload_ngrams, config, chunk_texts
    )
    return allowed, reason


def verify_with_debug(
    content: str,
    certificates: list[dict[str, Any]],
    payload_ngrams: set[tuple[str, ...]],
    config: dict[str, Any],
    chunk_texts: dict[str, str] | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Returns (allowed, reason, verifier_debug).

    verifier_debug is the structured diagnostic:
      {
        "check": "taint_integrity" | "ok",
        "taint": { ... full taint_detail output ... },
        "certificates_checked": int,
      }
    """
    taint_cfg = config.get("taint", {})
    threshold = taint_cfg.get("ngram_overlap_threshold", 0.02)

    detail = taint_detail(
        content,
        payload_ngrams,
        ngram_threshold=threshold,
        chunk_texts=chunk_texts,
    )

    debug: dict[str, Any] = {
        "check": "ok",
        "taint": detail,
        "certificates_checked": len(certificates),
    }

    if detail["tainted"]:
        debug["check"] = "taint_integrity"
        return False, "tainted", debug

    return True, "ok", debug
