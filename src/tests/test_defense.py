"""Tests for defense modules: allowlist, prompt formatting."""

from cert_agent_exp.defense.allowlist import allowlist_check
from cert_agent_exp.defense.prompt import format_retrieved_chunks


class TestAllowlistCheck:
    def test_allowed_type(self):
        action = {"type": "respond_answer", "raw_type": "respond_answer"}
        task = {"allowed_actions": ["respond_answer", "save_notes"]}
        ok, reason = allowlist_check(action, task)
        assert ok is True
        assert reason == "ok"

    def test_disallowed_type(self):
        action = {"type": "send_email", "raw_type": "send_email"}
        task = {"allowed_actions": ["respond_answer"]}
        ok, reason = allowlist_check(action, task)
        assert ok is False
        assert "not_allowed" in reason

    def test_raw_type_mismatch(self):
        action = {"type": "respond_answer", "raw_type": "send_email"}
        task = {"allowed_actions": ["respond_answer"]}
        ok, reason = allowlist_check(action, task)
        assert ok is False
        assert "raw_type" in reason

    def test_no_allowed_actions(self):
        action = {"type": "anything"}
        task = {}
        ok, reason = allowlist_check(action, task)
        assert ok is True

    def test_empty_action(self):
        ok, reason = allowlist_check({}, {"allowed_actions": ["respond_answer"]})
        assert ok is False


class TestFormatChunks:
    def test_none_mode(self):
        chunks = [{"id": "c1", "text": "hello"}]
        result = format_retrieved_chunks(chunks, defense="none")
        assert "hello" in result

    def test_quote_only(self):
        chunks = [{"id": "c1", "text": "hello"}]
        result = format_retrieved_chunks(chunks, defense="quote_only")
        assert "untrusted" in result.lower()
        assert "hello" in result

    def test_provenance_tags(self):
        chunks = [{"id": "c1", "text": "hello"}]
        result = format_retrieved_chunks(chunks, defense="provenance_tags")
        assert "c1" in result
        assert "hello" in result
