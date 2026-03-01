"""Retrieval over corpus index."""

from typing import Any, Optional

import numpy as np

from .embedder import Embedder
from .index_faiss import FaissFlatIPIndex


class CorpusRetriever:
    def __init__(
        self,
        index: FaissFlatIPIndex,
        embedder: Embedder,
        chunk_store: Optional[dict[str, str]] = None,
    ) -> None:
        self.index = index
        self.embedder = embedder
        self.chunk_store = chunk_store or {}

    def retrieve(self, query: str, k: int = 5) -> list[dict[str, Any]]:
        qv = self.embedder.embed([query])
        scores, indices = self.index.search(qv, k)
        out = []
        for s, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue
            chunk_id = self.index.get_id(int(idx))
            text = self.chunk_store.get(chunk_id, "")
            out.append({"id": chunk_id, "score": float(s), "text": text})
        return out
