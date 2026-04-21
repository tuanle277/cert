"""Tests for action_schema.py — JSON action parsing."""

from cert_agent_exp.agent.action_schema import parse_action, ALLOWED_ACTION_TYPES


class TestParseAction:
    def test_plain_text_fallback(self):
        result = parse_action("The answer is 42")
        assert result["type"] == "respond_answer"
        assert result["content"] == "The answer is 42"

    def test_json_fenced(self):
        output = '```json\n{"type": "respond_answer", "content": "hello"}\n```'
        result = parse_action(output)
        assert result["type"] == "respond_answer"
        assert result["content"] == "hello"

    def test_json_inline(self):
        output = 'Here is my answer: {"type": "save_notes", "content": "some notes"}'
        result = parse_action(output)
        assert result["type"] == "save_notes"
        assert result["content"] == "some notes"

    def test_raw_type_preserved(self):
        output = '{"type": "send_email", "content": "pwned"}'
        result = parse_action(output)
        assert result["raw_type"] == "send_email"
        assert result["type"] == "respond_answer"

    def test_used_sources_filtered(self):
        output = '{"type": "respond_answer", "content": "x", "used_sources": ["doc_1", "doc_99"]}'
        result = parse_action(output, exposed_sources=["doc_1", "doc_2"])
        assert result["used_sources"] == ["doc_1"]

    def test_certificate_parsed(self):
        output = '{"type": "respond_answer", "content": "x", "certificate": {"goal": "answer_question", "evidence": ["doc_1"], "constraints": []}}'
        result = parse_action(output, exposed_sources=["doc_1"])
        assert "certificate" in result
        assert result["certificate"]["goal"] == "answer_question"

    def test_empty_input(self):
        result = parse_action("")
        assert result["type"] == "respond_answer"
        assert result["content"] == ""

    def test_none_input(self):
        result = parse_action(None)
        assert result["type"] == "respond_answer"

    def test_all_allowed_types(self):
        for t in ALLOWED_ACTION_TYPES:
            output = f'{{"type": "{t}", "content": "test"}}'
            result = parse_action(output)
            assert result["type"] == t
