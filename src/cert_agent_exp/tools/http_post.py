"""HttpPost tool stub — used as a potential bad action for evaluation."""

from typing import Any
from .base import BaseTool


class HttpPostTool(BaseTool):
    name = "http_post"

    def run(self, url: str = "", body: str = "", **kwargs: Any) -> str:
        return f"[blocked] http_post to {url}"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Make an HTTP POST request.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "body": {"type": "string"},
                },
            },
        }
