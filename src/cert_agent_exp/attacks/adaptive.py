"""Adaptive strategies: goal_laundering, evidence_laundering, policy_mimicry (template selection)."""

from typing import Any

from .templates import load_templates, render_template


def select_template_for_strategy(
    strategy: str,
    payload_dir: str,
    payload: str,
) -> str:
    templates = load_templates(payload_dir)
    key = {
        "goal_laundering": "goal_laundering",
        "evidence_laundering": "evidence_laundering",
        "policy_mimicry": "policy_mimicry",
        "non_adaptive": "direct_override",
    }.get(strategy, "direct_override")
    tmpl = templates.get(key, "{{PAYLOAD}}")
    return render_template(tmpl, payload)
