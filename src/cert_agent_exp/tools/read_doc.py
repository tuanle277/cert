from typing import Any, List

from .base import BaseTool


class ReadDocTool(BaseTool):
    name = "read_doc"

    def __init__(self) -> None:
        self._last_doc_id: str = ""

    def run(self, doc_id: str = "", **kwargs: Any) -> str:
        self._last_doc_id = doc_id
        return f"[mock] content of doc {doc_id}"

    def get_last_exposed_sources(self) -> List[str]:
        return [self._last_doc_id] if self._last_doc_id else []

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Read a document by id.",
            "parameters": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
        }
