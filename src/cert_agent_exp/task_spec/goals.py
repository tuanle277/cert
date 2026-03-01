"""Goal text for tasks (e.g. from question field)."""

from typing import Any


def goal_from_instance(instance: dict[str, Any]) -> str:
    return instance.get("goal", "") or instance.get("question", "Answer the question.")
