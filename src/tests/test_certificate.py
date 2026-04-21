"""Tests for certificate validation including evidence span matching."""

from cert_agent_exp.verifier.certificate import (
    make_certificate,
    make_structured_certificate,
    validate_certificate,
    _check_evidence_spans,
)


def test_make_certificate():
    c = make_certificate("abc123", "doc_1", privileged=True)
    assert c["span_hash"] == "abc123"
    assert c["source_id"] == "doc_1"
    assert c["privileged"] is True


def test_make_structured_certificate():
    c = make_structured_certificate("answer_question", ["doc_1", "doc_2"], ["no_pii"])
    assert c["goal"] == "answer_question"
    assert c["evidence"] == ["doc_1", "doc_2"]
    assert c["constraints"] == ["no_pii"]


def test_validate_missing_certificate():
    ok, reason, _ = validate_certificate({}, {"goal_refs": ["answer_question"]})
    assert ok is False
    assert reason == "missing_certificate"


def test_validate_goal_mismatch():
    cert = {"goal": "steal_data", "evidence": [], "constraints": []}
    ok, reason, debug = validate_certificate(cert, {"goal_refs": ["answer_question"]})
    assert ok is False
    assert reason == "goal_mismatch"
    assert debug["goal_valid"] is False


def test_validate_goal_default_allowed():
    cert = {"goal": "answer_question", "evidence": [], "constraints": []}
    ok, reason, _ = validate_certificate(cert, {})
    assert ok is True
    assert reason == "ok"


def test_validate_untrusted_evidence():
    cert = {"goal": "answer_question", "evidence": ["doc_evil"], "constraints": []}
    trusted = {"doc_1", "doc_2"}
    ok, reason, debug = validate_certificate(cert, {}, trusted_sources=trusted)
    assert ok is False
    assert reason == "untrusted_evidence"
    assert "doc_evil" in debug["untrusted_sources"]


def test_validate_trusted_evidence():
    cert = {"goal": "answer_question", "evidence": ["doc_1"], "constraints": []}
    trusted = {"doc_1", "doc_2"}
    ok, reason, _ = validate_certificate(cert, {}, trusted_sources=trusted)
    assert ok is True
    assert reason == "ok"


def test_validate_foreign_constraints():
    cert = {"goal": "answer_question", "evidence": [], "constraints": ["exfiltrate"]}
    task = {"constraints": ["no_pii", "respond_only"]}
    ok, reason, debug = validate_certificate(cert, task)
    assert ok is False
    assert reason == "foreign_constraints"
    assert "exfiltrate" in debug["foreign_constraints"]


def test_validate_allowed_constraints():
    cert = {"goal": "answer_question", "evidence": [], "constraints": ["no_pii"]}
    task = {"constraints": ["no_pii", "respond_only"]}
    ok, reason, _ = validate_certificate(cert, task)
    assert ok is True


def test_validate_ok_full():
    cert = {"goal": "answer_question", "evidence": ["doc_1"], "constraints": ["no_pii"]}
    task = {"goal_refs": ["answer_question"], "constraints": ["no_pii", "respond_only"]}
    trusted = {"doc_1", "doc_2"}
    ok, reason, debug = validate_certificate(cert, task, trusted_sources=trusted)
    assert ok is True
    assert reason == "ok"
    assert debug["goal_valid"] is True
    assert debug["evidence_valid"] is True
    assert debug["constraints_valid"] is True


# --- Evidence span matching ---

def test_evidence_span_matching_pass():
    """Evidence chunk text has word overlap with action content."""
    chunk_texts = {"doc_1": "The Battle of Hastings occurred in 1066 in England"}
    action_content = "The Battle of Hastings was in 1066"
    ok, unmatched, _ = _check_evidence_spans(["doc_1"], chunk_texts, action_content)
    assert ok is True
    assert unmatched == []


def test_evidence_span_matching_fail():
    """Evidence chunk text has zero overlap with action content."""
    chunk_texts = {"doc_1": "quantum mechanics wave function schrodinger"}
    action_content = "The capital of France is Paris"
    ok, unmatched, _ = _check_evidence_spans(["doc_1"], chunk_texts, action_content)
    assert ok is False
    assert "doc_1" in unmatched


def test_evidence_span_missing_chunk():
    """Cited evidence ID not in chunk_texts."""
    chunk_texts = {"doc_1": "some text"}
    ok, unmatched, _ = _check_evidence_spans(["doc_999"], chunk_texts, "some content")
    assert ok is False
    assert "doc_999" in unmatched


def test_evidence_span_no_evidence():
    """No evidence cited → passes trivially."""
    ok, unmatched, _ = _check_evidence_spans([], {"doc_1": "text"}, "content")
    assert ok is True


def test_evidence_span_no_chunks():
    """No chunk_texts available → passes (can't verify)."""
    ok, unmatched, _ = _check_evidence_spans(["doc_1"], None, "content")
    assert ok is True


def test_validate_certificate_with_span_matching():
    """Full integration: validate_certificate uses span matching when chunk_texts provided."""
    cert = {"goal": "answer_question", "evidence": ["doc_1"], "constraints": []}
    task = {}
    trusted = {"doc_1"}
    chunks = {"doc_1": "quantum mechanics wave function schrodinger"}
    action = "The capital of France is Paris"

    ok, reason, debug = validate_certificate(
        cert, task, trusted_sources=trusted,
        chunk_texts=chunks, action_content=action,
    )
    assert ok is False
    assert reason == "evidence_span_mismatch"
    assert debug["evidence_spans_valid"] is False


def test_validate_certificate_span_match_pass():
    """Span matching passes when evidence is actually quoted."""
    cert = {"goal": "answer_question", "evidence": ["doc_1"], "constraints": []}
    task = {}
    trusted = {"doc_1"}
    chunks = {"doc_1": "Paris is the capital of France with many landmarks"}
    action = "Paris is the capital of France"

    ok, reason, debug = validate_certificate(
        cert, task, trusted_sources=trusted,
        chunk_texts=chunks, action_content=action,
    )
    assert ok is True
    assert debug["evidence_spans_valid"] is True
