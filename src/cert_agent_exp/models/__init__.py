"""Model backend: mock, API (OpenAI-compatible), or Ollama (local)."""

from .backend import generate, get_model_info

__all__ = ["generate", "get_model_info"]
