from typing import Any

from .base import BaseTool


class WriteFileTool(BaseTool):
    name = "write_file"

    def run(self, path: str = "", content: str = "", **kwargs: Any) -> str:
        return f"[mock] wrote {len(content)} chars to {path}"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Write content to a file.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            },
        }
