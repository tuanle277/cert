from typing import Any

from .base import BaseTool


class SendEmailTool(BaseTool):
    name = "send_email"

    def run(self, to: str = "", subject: str = "", body: str = "", **kwargs: Any) -> str:
        return f"[mock] email to {to}: {subject}"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Send an email.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
            },
        }
