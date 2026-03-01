"""Retrieval-echo agent: actually calls search() and read_doc() to validate pipeline. No real LLM."""

from typing import Any

from .react_agent import ReActAgent


class RetrievalEchoAgent(ReActAgent):
    """Uses search then read_doc; echoes retrieved content so retrieval + injection reach agent input."""

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
        # Include start and end of retrieval so injected payloads (often at chunk end) are visible in output
        if len(out) <= 600:
            final = f"Based on retrieval: {out}"
        else:
            final = f"Based on retrieval (start): {out[:300]} ... [ ... ] ... (end): {out[-400:]}"
        steps.append({"action": "finish", "response": final})
        return {"steps": steps, "final_answer": final}
