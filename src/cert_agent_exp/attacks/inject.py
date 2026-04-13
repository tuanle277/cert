"""Inject a payload string into a document chunk."""


def inject_into_text(
    text: str,
    payload: str,
    placement: str = "suffix",
) -> str:
    """Splice *payload* into *text* at the given placement.

    Placements: suffix (default), prefix, middle.
    """
    if placement == "prefix":
        return payload + "\n\n" + text
    if placement == "middle":
        sentences = text.split(". ")
        mid = len(sentences) // 2
        before = ". ".join(sentences[:mid])
        after = ". ".join(sentences[mid:])
        return before + ".\n\n" + payload + "\n\n" + after
    return text + "\n\n" + payload
