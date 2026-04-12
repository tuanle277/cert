"""Corpus retriever: embed query → FAISS search → return chunks."""

from __future__ import annotations

import numpy as np
from typing import Any

from .embedder import Embedder
from .index import FaissFlatIPIndex


class CorpusRetriever:
    """Retrieves top-k chunks from an indexed corpus."""

    def __init__(
        self,
        index: FaissFlatIPIndex,
        embedder: Embedder,
        chunk_store: dict[str, str],
    ) -> None:
        self.index = index
        self.embedder = embedder
        self.chunk_store = chunk_store
        self._id_list = list(chunk_store.keys())

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        q_vec = self.embedder.encode([query])
        scores, indices = self.index.search(q_vec, top_k=top_k)

        results: list[dict[str, Any]] = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self._id_list):
                continue
            cid = self._id_list[idx]
            results.append({
                "id": cid,
                "text": self.chunk_store.get(cid, ""),
                "score": float(score),
            })
        return results
