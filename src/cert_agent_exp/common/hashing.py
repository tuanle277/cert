import hashlib
import re


def content_hash(text: str) -> str:
    """SHA256 hash of text for span/content identity."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    """Canonical form for hashing and deterministic chunking: single spaces, no leading/trailing whitespace."""
    if not text:
        return ""
    return " ".join(text.split())
