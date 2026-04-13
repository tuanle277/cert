"""Token budget enforcement for attack payloads."""


def apply_budget(payload: str, B: int) -> str:
    """Truncate *payload* to at most *B* whitespace-delimited tokens."""
    if B <= 0:
        return payload
    tokens = payload.split()
    if len(tokens) <= B:
        return payload
    return " ".join(tokens[:B])
