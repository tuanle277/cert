import numpy as np
from cert_agent_exp.corpus import FaissFlatIPIndex


def test_faiss_index():
    dim = 4
    index = FaissFlatIPIndex(dim)
    vecs = np.random.randn(2, dim).astype(np.float32)
    index.add(vecs)
    scores, indices = index.search(vecs[:1], top_k=2)
    assert scores.shape == (1, 2)
    assert index.ntotal == 2
