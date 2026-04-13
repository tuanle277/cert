"""Base class for all agent tools."""

from typing import Any


class BaseTool:
    name: str = "base"

    def run(self, **kwargs: Any) -> str:
        raise NotImplementedError

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": "", "parameters": {}}
