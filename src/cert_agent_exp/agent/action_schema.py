"""Structured action schema and parser for agent outputs.

Actions are machine-readable: type, content, used_sources.
Parser accepts raw agent output (e.g. final_answer) and exposed_sources;
returns a validated action dict or raises/returns parse failure.
"""

import json
import re
from typing import Any

# Allowed action types for the benchmark (QA + optional future tools)
ALLOWED_ACTION_TYPES = frozenset({"respond_answer", "save_notes", "request_more_info"})

# JSON schema for a single action (for validation/logging)
ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": list(ALLOWED_ACTION_TYPES)},
        "content": {"type": "string"},
        "used_sources": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["type", "content"],
    "additionalProperties": False,
}


def parse_action(
    agent_output: str,
    exposed_sources: list[str] | None = None,
    default_type: str = "respond_answer",
) -> dict[str, Any]:
    """Parse agent output into a structured action.

    - Tries to find a JSON block (```json ... ``` or last {...}) and validate.
    - If parsing fails or no valid action, returns a fallback action:
      type=default_type, content=agent_output, used_sources=exposed_sources or [].
    - used_sources in parsed JSON are restricted to exposed_sources when provided.
    """
    exposed = list(exposed_sources or [])
    fallback = {
        "type": default_type,
        "content": (agent_output or "").strip(),
        "used_sources": exposed,
    }

    if not (agent_output or "").strip():
        return fallback

    # Try ```json ... ``` block first
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", agent_output)
    if m:
        try:
            obj = json.loads(m.group(1).strip())
            return _validate_and_normalize_action(obj, exposed, fallback)
        except (json.JSONDecodeError, TypeError):
            pass

    # Try last JSON object in the text
    for match in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", agent_output):
        try:
            obj = json.loads(match.group(0))
            if isinstance(obj, dict) and "type" in obj:
                return _validate_and_normalize_action(obj, exposed, fallback)
        except (json.JSONDecodeError, TypeError):
            continue

    return fallback


def _validate_and_normalize_action(
    obj: dict[str, Any],
    exposed_sources: list[str],
    fallback: dict[str, Any],
) -> dict[str, Any]:
    """Validate type/content/used_sources and restrict used_sources to exposed."""
    action_type = obj.get("type")
    if action_type not in ALLOWED_ACTION_TYPES:
        action_type = fallback["type"]
    content = obj.get("content")
    if content is None:
        content = fallback["content"]
    else:
        content = str(content).strip()
    used = obj.get("used_sources")
    if not isinstance(used, list):
        used = fallback["used_sources"]
    else:
        used = [str(s) for s in used if s in exposed_sources]
    return {
        "type": action_type,
        "content": content,
        "used_sources": used,
    }
