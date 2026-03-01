"""Search tool: faiss (index) or distractor (fixed context_paragraphs). Returns provenance IDs for logging."""

from typing import Any, List

from .base import BaseTool


class SearchTool(BaseTool):
    name = "search"

    def __init__(
        self,
        retriever: Any = None,
        max_results: int = 10,
        retrieval_mode: str = "faiss",
    ) -> None:
        self.retriever = retriever
        self.max_results = max_results
        self.retrieval_mode = retrieval_mode
        self.current_task: dict[str, Any] | None = None
        self._last_hits: List[dict[str, Any]] = []

    def run(self, query: str = "", **kwargs: Any) -> str:
        self._last_hits = []
        if self.retrieval_mode == "distractor" and self.current_task:
            titles = self.current_task.get("context_titles", [])
            paras = self.current_task.get("context_paragraphs", [])
            if paras:
                for i, (title, text) in enumerate(zip(titles, paras)):
                    if i >= self.max_results:
                        break
                    self._last_hits.append({"id": title, "text": text})
                return "\n\n".join(h["text"] for h in self._last_hits)
        if self.retriever:
            hits = self.retriever.retrieve(query, k=self.max_results)
            self._last_hits = hits
            return "\n\n".join(h.get("text", "") for h in hits)
        return "[mock] search results for: " + query

    def get_last_exposed_sources(self) -> List[str]:
        """Provenance IDs shown to the model (for run log exposed_sources)."""
        return [h.get("id", "") for h in self._last_hits if h.get("id")]

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Search the knowledge base.",
            "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
        }
