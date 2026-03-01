"""Certificate representation: span hash, provenance, privileged flag."""

from typing import Any


def make_certificate(
    span_hash: str,
    source_id: str,
    privileged: bool = False,
) -> dict[str, Any]:
    return {
        "span_hash": span_hash,
        "source_id": source_id,
        "privileged": privileged,
    }
