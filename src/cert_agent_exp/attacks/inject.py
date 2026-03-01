"""Inject payload into corpus chunks or tool output (prefix/suffix/middle)."""

import random
from typing import Literal

Placement = Literal["prefix", "suffix", "middle"]


def inject_into_text(
    text: str,
    payload: str,
    placement: Placement = "suffix",
) -> str:
    if placement == "prefix":
        return payload + "\n\n" + text
    if placement == "suffix":
        return text + "\n\n" + payload
    if placement == "middle":
        parts = text.split("\n\n")
        i = len(parts) // 2 if parts else 0
        parts.insert(i, payload)
        return "\n\n".join(parts)
    return text
