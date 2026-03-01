import numpy as np
from cert_agent_exp.corpus import Embedder, FaissFlatIPIndex, CorpusRetriever

def test_faiss_index():
    dim = 4
    index = FaissFlatIPIndex(dim)
    ids = ["a", "b"]
    vecs = np.random.randn(2, dim).astype(np.float32)
    index.add(ids, vecs)
    scores, indices = index.search(vecs[:1], k=2)
    assert scores.shape == (1, 2)
    assert index.get_id(0) == "a"
