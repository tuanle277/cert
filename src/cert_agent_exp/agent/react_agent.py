"""ReAct-style agent: think -> act -> observe loop with mock model."""

from typing import Any

from .prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE


class ReActAgent:
    def __init__(self, tools: list[Any], max_steps: int = 12, model_mode: str = "mock") -> None:
        self.tools = {t.name: t for t in tools}
        self.max_steps = max_steps
        self.model_mode = model_mode

    def run(self, goal: str) -> dict[str, Any]:
        steps = []
        for _ in range(self.max_steps):
            # Mock: always "finish" with a benign answer
            steps.append({"action": "finish", "response": "[mock] Answer: completed."})
            break
        return {"steps": steps, "final_answer": "[mock] completed."}
