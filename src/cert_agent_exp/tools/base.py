"""Base tool interface for the agent. Provenance: get_last_exposed_sources() for run logs."""

from abc import ABC, abstractmethod
from typing import Any, List


class BaseTool(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, **kwargs: Any) -> str:
        pass

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": "", "parameters": {}}

    def get_last_exposed_sources(self) -> List[str]:
        """IDs of sources (chunk_id, doc_id) returned to the model. For run log exposed_sources."""
        return []
