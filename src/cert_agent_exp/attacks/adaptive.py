"""Adaptive strategy selection: pick the right template for a strategy name."""

import os
from .templates import load_templates, render_template

STRATEGY_TO_TEMPLATE = {
    "non_adaptive": "direct_override",
    "direct_override": "direct_override",
    "goal_laundering": "goal_laundering",
    "evidence_laundering": "evidence_laundering",
    "policy_mimicry": "policy_mimicry",
    "subtle_redirect": "subtle_redirect",
    "footnote_injection": "footnote_injection",
    "context_poisoning": "context_poisoning",
    "helpful_assistant": "helpful_assistant",
}


def select_template_for_strategy(
    strategy: str,
    payload_dir: str,
    base_payload: str,
) -> str:
    """Return the rendered payload for *strategy*.

    Falls back to the raw *base_payload* if no matching template exists.
    """
    tmpl_name = STRATEGY_TO_TEMPLATE.get(strategy, strategy)
    templates = load_templates(payload_dir)
    tmpl = templates.get(tmpl_name)
    if tmpl:
        return render_template(tmpl, base_payload)
    return base_payload
