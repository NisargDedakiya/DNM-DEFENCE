from unittest.mock import MagicMock, patch

import pytest

from llm_output_sanitizer import (
    strip_xss, detect_pii, detect_pii_semantic, detect_prompt_leakage, validate_json_schema, sanitize,
)


def test_strip_xss_removes_script_tags():
    assert strip_xss("<script>alert(1)</script>Hello") == "Hello"


def test_strip_xss_removes_all_markup_by_default():
    assert strip_xss("<b>bold</b> and <a href='x'>link</a>") == "bold and link"


def test_strip_xss_passthrough_for_plain_text():
    assert strip_xss("just plain text") == "just plain text"


def test_strip_xss_handles_empty_string():
    assert strip_xss("") == ""


def test_detect_pii_finds_email():
    hits = detect_pii("Contact me at jane@example.com for details.")
    assert any(h["type"] == "email" and h["match"] == "jane@example.com" for h in hits)


def test_detect_pii_finds_us_phone():
    hits = detect_pii("Call me at (555) 123-4567 tomorrow.")
    assert any(h["type"] == "phone_us" for h in hits)


def test_detect_pii_finds_ssn():
    hits = detect_pii("SSN: 123-45-6789")
    assert any(h["type"] == "ssn_us" for h in hits)


def test_detect_pii_empty_text_returns_no_hits():
    assert detect_pii("") == []


def test_detect_pii_clean_text_returns_no_hits():
    assert detect_pii("The weather is nice today.") == []


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def test_detect_pii_semantic_parses_claude_response():
    fake_client = MagicMock()
    resp = MagicMock()
    resp.content = [_text_block("full_name: Jane Doe\naddress: 123 Main St, Springfield")]
    fake_client.messages.create.return_value = resp

    with patch("anthropic.Anthropic", return_value=fake_client):
        hits = detect_pii_semantic("Jane Doe lives at 123 Main St, Springfield.", anthropic_api_key="fake-key")

    assert {"type": "full_name", "match": "Jane Doe"} in hits
    assert any(h["type"] == "address" for h in hits)


def test_detect_pii_semantic_handles_none_response():
    fake_client = MagicMock()
    resp = MagicMock()
    resp.content = [_text_block("NONE")]
    fake_client.messages.create.return_value = resp

    with patch("anthropic.Anthropic", return_value=fake_client):
        hits = detect_pii_semantic("Nothing sensitive here.", anthropic_api_key="fake-key")
    assert hits == []


def test_detect_prompt_leakage_flags_common_phrases():
    hits = detect_prompt_leakage("Sure! As an AI language model, I was instructed to always be polite.")
    types_found = {h["type"] for h in hits}
    assert "leakage_phrase" in types_found


def test_detect_prompt_leakage_flags_system_prompt_overlap():
    system_prompt = "You are a customer support agent for Acme Corp. Always be polite and never discuss competitors under any circumstances."
    leaked_output = "You are a customer support agent for Acme Corp. Always be polite and never discuss competitors"
    hits = detect_prompt_leakage(leaked_output, system_prompt=system_prompt)
    assert any(h["type"] == "system_prompt_overlap" for h in hits)


def test_detect_prompt_leakage_clean_output_no_hits():
    system_prompt = "You are a customer support agent for Acme Corp."
    assert detect_prompt_leakage("The order will ship in 3-5 business days.", system_prompt=system_prompt) == []


def test_validate_json_schema_valid_data():
    schema = {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}
    is_valid, errors = validate_json_schema({"name": "Jane"}, schema)
    assert is_valid is True
    assert errors == []


def test_validate_json_schema_invalid_data_reports_errors():
    schema = {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}
    is_valid, errors = validate_json_schema({}, schema)
    assert is_valid is False
    assert len(errors) == 1


def test_sanitize_combines_all_checks():
    result = sanitize("<script>bad()</script>Contact jane@example.com", system_prompt=None)
    assert result["sanitized_text"] == "Contact jane@example.com"
    assert any(h["type"] == "email" for h in result["pii_hits"])
    assert result["prompt_leakage_hits"] == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
