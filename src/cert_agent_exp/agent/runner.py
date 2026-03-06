"""Run one episode: load task, run agent, record log with exposed_sources and parsed_action."""

from typing import Any, List

from .react_agent import ReActAgent
from .planner_executor import PlannerExecutorAgent
from .retrieval_echo_agent import RetrievalEchoAgent
from .action_schema import parse_action


def _collect_exposed_sources(tools: List[Any]) -> List[str]:
    out: List[str] = []
    for t in tools:
        if hasattr(t, "get_last_exposed_sources"):
            out.extend(t.get_last_exposed_sources())
    return out


def run_episode(
    task: dict[str, Any],
    tools: list[Any],
    agent_type: str = "react",
    max_steps: int = 12,
    model_mode: str = "mock",
    model_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Set current_task for distractor search
    for t in tools:
        if hasattr(t, "current_task"):
            t.current_task = task
    goal = task.get("goal", "")
    mcfg = model_config or {}
    if agent_type == "planner_executor":
        agent = PlannerExecutorAgent(tools, max_steps=max_steps, model_mode=model_mode, model_config=mcfg)
    elif agent_type == "retrieval_echo":
        agent = RetrievalEchoAgent(tools, max_steps=max_steps, model_mode=model_mode, model_config=mcfg)
    else:
        agent = ReActAgent(tools, max_steps=max_steps, model_mode=model_mode, model_config=mcfg)
    result = agent.run(goal)
    exposed_sources = _collect_exposed_sources(tools)
    final_answer = result.get("final_answer", "")
    parsed_action = parse_action(final_answer, exposed_sources, default_type="respond_answer")
    return {
        "task_id": task.get("task_id", ""),
        "steps": result.get("steps", []),
        "final_answer": final_answer,
        "parsed_action": parsed_action,
        "success": True,
        "exposed_sources": exposed_sources,
        "injected_sources": [],  # filled by grid runner from injection_manifest
        "verifier_decision": None,
        "rejection_reason": None,
    }
