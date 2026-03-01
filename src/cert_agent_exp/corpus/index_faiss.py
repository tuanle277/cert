"""FAISS flat IP index for corpus chunks."""

import os
from typing import Any, Optional

import numpy as np


class FaissFlatIPIndex:
    def __init__(self, dim: int) -> None:
        self.dim = dim
        self._index: Optional[Any] = None
        self._id_list: list[str] = []

    def add(self, ids: list[str], vectors: np.ndarray) -> None:
        import faiss
        if self._index is None:
            self._index = faiss.IndexFlatIP(vectors.shape[1])
        vectors = vectors.astype(np.float32)
        faiss.normalize_L2(vectors)
        self._index.add(vectors)
        self._id_list.extend(ids)

    def search(self, query_vectors: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray]:
        import faiss
        if self._index is None:
            raise RuntimeError("Index is empty")
        q = query_vectors.astype(np.float32)
        faiss.normalize_L2(q)
        scores, indices = self._index.search(q, k)
        return scores, indices

    def get_id(self, idx: int) -> str:
        return self._id_list[idx]

    def save(self, path: str) -> None:
        import faiss
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        faiss.write_index(self._index, path)
        id_path = path + ".ids"
        with open(id_path, "w", encoding="utf-8") as f:
            for i in self._id_list:
                f.write(i + "\n")

    def load(self, path: str) -> None:
        import faiss
        self._index = faiss.read_index(path)
        id_path = path + ".ids"
        self._id_list = []
        with open(id_path, "r", encoding="utf-8") as f:
            for line in f:
                self._id_list.append(line.rstrip("\n"))
