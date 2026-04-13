"""Load and render attack payload templates from assets/attack_payloads/."""

import os
from typing import Dict


def load_templates(payload_dir: str) -> Dict[str, str]:
    """Load all .txt templates from *payload_dir*.  Returns {name: template}."""
    templates: Dict[str, str] = {}
    if not os.path.isdir(payload_dir):
        return templates
    for fname in sorted(os.listdir(payload_dir)):
        if not fname.endswith(".txt"):
            continue
        name = fname.removesuffix(".txt")
        with open(os.path.join(payload_dir, fname), "r", encoding="utf-8") as f:
            templates[name] = f.read().strip()
    return templates


def render_template(template: str, payload: str) -> str:
    """Replace ``{{PAYLOAD}}`` placeholder with the actual payload text."""
    return template.replace("{{PAYLOAD}}", payload)
