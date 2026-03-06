"""Adaptive strategies: goal_laundering, evidence_laundering, policy_mimicry, and harder variants."""

from typing import Any

from .templates import load_templates, render_template

STRATEGY_TO_TEMPLATE = {
    "non_adaptive": "direct_override",
    "goal_laundering": "goal_laundering",
    "evidence_laundering": "evidence_laundering",
    "policy_mimicry": "policy_mimicry",
    "authority_update": "authority_policy_update",
    "tool_schema": "tool_schema_attack",
    "subtle_redirect": "subtle_redirect",
    "context_poisoning": "context_poisoning",
    "helpful_assistant": "helpful_assistant",
    "footnote_injection": "footnote_injection",
}


def select_template_for_strategy(
    strategy: str,
    payload_dir: str,
    payload: str,
) -> str:
    templates = load_templates(payload_dir)
    key = STRATEGY_TO_TEMPLATE.get(strategy, "direct_override")
    tmpl = templates.get(key, "{{PAYLOAD}}")
    return render_template(tmpl, payload)
