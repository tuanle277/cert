"""Planner-executor agent (stub)."""

from typing import Any

from .react_agent import ReActAgent


class PlannerExecutorAgent(ReActAgent):
    """Same as ReAct for now; can be extended with plan-first step."""

    def run(self, goal: str) -> dict[str, Any]:
        return super().run(goal)
