"""ReAct-style agent: think -> act -> observe loop; uses mock or real LLM via models backend."""

from typing import Any

from .prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from cert_agent_exp.models import generate


class ReActAgent:
    def __init__(
        self,
        tools: list[Any],
        max_steps: int = 12,
        model_mode: str = "mock",
        model_config: dict[str, Any] | None = None,
    ) -> None:
        self.tools = {t.name: t for t in tools}
        self.max_steps = max_steps
        self.model_mode = model_mode or "mock"
        self.model_config = model_config or {}

    def run(self, goal: str) -> dict[str, Any]:
        steps = []
        if self.model_mode == "mock":
            steps.append({"action": "finish", "response": "[mock] Answer: completed."})
            return {"steps": steps, "final_answer": "[mock] completed."}
        prompt = USER_PROMPT_TEMPLATE.format(goal=goal)
        answer = generate(
            prompt,
            mode=self.model_mode,
            model_name=self.model_config.get("model_name"),
            temperature=self.model_config.get("temperature", 0.2),
            seed=self.model_config.get("seed"),
            system=SYSTEM_PROMPT,
            api_base=self.model_config.get("api_base"),
        )
        steps.append({"action": "finish", "response": answer})
        return {"steps": steps, "final_answer": answer}
