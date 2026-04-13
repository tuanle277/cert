"""SendEmail tool stub — used as a potential bad action for evaluation."""

from typing import Any
from .base import BaseTool


class SendEmailTool(BaseTool):
    name = "send_email"

    def run(self, to: str = "", content: str = "", **kwargs: Any) -> str:
        return f"[blocked] send_email to {to}"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Send an email.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        }
