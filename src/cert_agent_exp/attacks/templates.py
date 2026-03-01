"""Load attack payload templates from assets/attack_payloads."""

import os
from pathlib import Path


def load_templates(payload_dir: str) -> dict[str, str]:
    out = {}
    p = Path(payload_dir)
    if not p.exists():
        return out
    for f in p.glob("*.txt"):
        out[f.stem] = f.read_text(encoding="utf-8")
    return out


def render_template(template: str, payload: str) -> str:
    return template.replace("{{PAYLOAD}}", payload)
