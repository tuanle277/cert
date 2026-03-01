"""Embedding model wrapper (sentence-transformers)."""

from typing import Any, Optional

import numpy as np


class Embedder:
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> None:
        self._model_name = model_name
        self._model: Optional[Any] = None

    def _load(self) -> None:
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer
        self._model = SentenceTransformer(self._model_name)

    def embed(self, texts: list[str]) -> np.ndarray:
        self._load()
        return self._model.encode(texts, show_progress_bar=False)
