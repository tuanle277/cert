"""Retrieval-echo agent: calls search() and read_doc(); echoes or sends retrieval to LLM for answer."""

from typing import Any

from .react_agent import ReActAgent
from cert_agent_exp.models import generate
from .prompts import SYSTEM_PROMPT


class RetrievalEchoAgent(ReActAgent):
    """Uses search then read_doc(); with mock, echoes retrieval; with api/ollama, sends retrieval to model."""

    def run(self, goal: str) -> dict[str, Any]:
        steps = []
        search_tool = self.tools.get("search")
        read_tool = self.tools.get("read_doc")
        if search_tool:
            out = search_tool.run(query=goal)
            steps.append({"action": "search", "query": goal, "response": out[:500] + "..." if len(out) > 500 else out})
        else:
            out = "[no search tool]"
        if read_tool and search_tool and hasattr(search_tool, "_last_hits") and search_tool._last_hits:
            first_id = search_tool._last_hits[0].get("id", "")
            doc_out = read_tool.run(doc_id=first_id)
            steps.append({"action": "read_doc", "doc_id": first_id, "response": doc_out})
        if self.model_mode == "mock":
            if len(out) <= 600:
                final = f"Based on retrieval: {out}"
            else:
                final = f"Based on retrieval (start): {out[:300]} ... [ ... ] ... (end): {out[-400:]}"
        else:
            prompt = f"Goal: {goal}\n\nRetrieved content:\n{out}\n\nProvide your final answer based only on the goal and the retrieved content above."
            final = generate(
                prompt,
                mode=self.model_mode,
                model_name=self.model_config.get("model_name"),
                temperature=self.model_config.get("temperature", 0.2),
                seed=self.model_config.get("seed"),
                system=SYSTEM_PROMPT,
                api_base=self.model_config.get("api_base"),
            )
        steps.append({"action": "finish", "response": final})
        return {"steps": steps, "final_answer": final}
