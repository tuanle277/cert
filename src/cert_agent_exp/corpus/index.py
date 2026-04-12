"""FAISS flat inner-product index wrapper."""

from __future__ import annotations

import numpy as np
from typing import Any


class FaissFlatIPIndex:
    """Thin wrapper around faiss.IndexFlatIP for retrieval."""

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim
        self._index: Any = None

    def _ensure_index(self) -> None:
        if self._index is not None:
            return
        import faiss
        self._index = faiss.IndexFlatIP(self.dim)

    def add(self, vectors: np.ndarray) -> None:
        self._ensure_index()
        if vectors.dtype != np.float32:
            vectors = vectors.astype(np.float32)
        import faiss
        faiss.normalize_L2(vectors)
        self._index.add(vectors)

    def search(self, query_vectors: np.ndarray, top_k: int = 5) -> tuple[np.ndarray, np.ndarray]:
        self._ensure_index()
        if query_vectors.dtype != np.float32:
            query_vectors = query_vectors.astype(np.float32)
        import faiss
        faiss.normalize_L2(query_vectors)
        scores, indices = self._index.search(query_vectors, top_k)
        return scores, indices

    def save(self, path: str) -> None:
        self._ensure_index()
        import faiss
        faiss.write_index(self._index, path)

    def load(self, path: str) -> None:
        import faiss
        self._index = faiss.read_index(path)
        self.dim = self._index.d

    @property
    def ntotal(self) -> int:
        if self._index is None:
            return 0
        return self._index.ntotal
