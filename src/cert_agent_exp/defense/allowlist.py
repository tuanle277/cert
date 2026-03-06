"""Static allowlist policy for structured actions.

Checks both the normalized `type` and the pre-normalization `raw_type`.
If the model *tried* to use a disallowed action (e.g. send_email), this blocks
it even though the parser may have normalized the type to respond_answer.
"""

from typing import Any, Tuple


def allowlist_check(action: dict[str, Any], task_spec: dict[str, Any]) -> Tuple[bool, str]:
    """Return (allowed, reason) for a structured action under a task spec.

    Checks both `type` (normalized) and `raw_type` (what model actually produced).
    Either being disallowed triggers a block.
    """
    if not action:
        return False, "no_action"
    allowed_actions = task_spec.get("allowed_actions") or []
    if not allowed_actions:
        return True, "ok"

    action_type = action.get("type", "")
    raw_type = action.get("raw_type", action_type)

    if action_type not in allowed_actions:
        return False, f"action_type_not_allowed:{action_type}"
    if raw_type not in allowed_actions:
        return False, f"raw_type_not_allowed:{raw_type}"
    return True, "ok"

