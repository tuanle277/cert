from typing import Any

from .base import BaseTool


class HttpPostTool(BaseTool):
    name = "http_post"

    def run(self, url: str = "", body: str = "", **kwargs: Any) -> str:
        return f"[mock] POST {url} -> 200"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Send HTTP POST request.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
            },
        }
