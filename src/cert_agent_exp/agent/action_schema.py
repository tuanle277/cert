"""Structured action schema and parser for agent outputs.

Actions are machine-readable: type, content, used_sources.
Parser accepts raw agent output (e.g. final_answer) and exposed_sources;
returns a validated action dict or raises/returns parse failure.

The parser preserves `raw_type` (the type the model actually produced) alongside
`type` (the normalized/validated type). This lets the allowlist defense check
what the model *tried* to do, even if it wasn't a recognized action type.
"""

import json
import re
from typing import Any

ALLOWED_ACTION_TYPES = frozenset({"respond_answer", "save_notes", "request_more_info"})

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

    Returns a dict with: type, raw_type, content, used_sources;
    optional **certificate** `{goal, evidence, constraints}` when present in JSON.
    `raw_type` preserves whatever the model produced before normalization.
    """
    exposed = list(exposed_sources or [])
    fallback = {
        "type": default_type,
        "raw_type": default_type,
        "content": (agent_output or "").strip(),
        "used_sources": exposed,
    }

    if not (agent_output or "").strip():
        return fallback

    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", agent_output)
    if m:
        try:
            obj = json.loads(m.group(1).strip())
            return _validate_and_normalize_action(obj, exposed, fallback)
        except (json.JSONDecodeError, TypeError):
            pass

    for match in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", agent_output):
        try:
            obj = json.loads(match.group(0))
            if isinstance(obj, dict) and "type" in obj:
                return _validate_and_normalize_action(obj, exposed, fallback)
        except (json.JSONDecodeError, TypeError):
            continue

    return fallback


def _normalize_certificate(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Extract optional φ = (goal, evidence, constraints) from parsed JSON."""
    cert = obj.get("certificate")
    if not isinstance(cert, dict):
        return None
    goal = cert.get("goal", "")
    goal = str(goal).strip() if goal is not None else ""
    ev_raw = cert.get("evidence", [])
    evidence: list[str] = []
    if isinstance(ev_raw, list):
        evidence = [str(e).strip() for e in ev_raw if e is not None]
    c_raw = cert.get("constraints", [])
    constraints: list[str] = []
    if isinstance(c_raw, list):
        constraints = [str(c).strip() for c in c_raw if c is not None]
    elif isinstance(c_raw, str) and c_raw.strip():
        constraints = [c_raw.strip()]
    if not goal and not evidence and not constraints:
        return None
    return {"goal": goal, "evidence": evidence, "constraints": constraints}


def _validate_and_normalize_action(
    obj: dict[str, Any],
    exposed_sources: list[str],
    fallback: dict[str, Any],
) -> dict[str, Any]:
    """Validate type/content/used_sources. Preserves raw_type before normalization."""
    raw_type = obj.get("type", fallback["type"])
    action_type = raw_type if raw_type in ALLOWED_ACTION_TYPES else fallback["type"]
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
    out: dict[str, Any] = {
        "type": action_type,
        "raw_type": raw_type,
        "content": content,
        "used_sources": used,
    }
    cert = _normalize_certificate(obj)
    if cert is not None:
        out["certificate"] = cert
    return out
