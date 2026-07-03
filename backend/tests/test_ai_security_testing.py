import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import Client, Finding
from app.services import ai_security_testing


def _make_client(db):
    c = Client(id=str(uuid.uuid4()), name="AI Test Co", root_domain="ai-test.example.com",
               contact_email="a@ai-test.example.com")
    db.add(c)
    db.commit()
    return c


def test_payload_library_covers_all_four_categories():
    categories = {p["category"] for p in ai_security_testing.PROMPT_INJECTION_PAYLOADS}
    assert categories == {"direct_injection", "indirect_injection", "jailbreak", "system_prompt_extraction"}
    assert len(ai_security_testing.PROMPT_INJECTION_PAYLOADS) >= 40


def _fake_async_client(response_text="I cannot help with that.", status_code=200, raises=False):
    fake_client = AsyncMock()
    if raises:
        fake_client.post.side_effect = __import__("httpx").ConnectError("down")
    else:
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = response_text
        fake_client.post.return_value = resp
    fake_client.__aenter__.return_value = fake_client
    fake_client.__aexit__.return_value = False
    return fake_client


def test_run_prompt_injection_suite_delivers_every_payload():
    fake_client = _fake_async_client()
    with patch("app.services.ai_security_testing.httpx.AsyncClient", return_value=fake_client):
        results = asyncio.run(ai_security_testing.run_prompt_injection_suite("https://target.example.com/chat"))
    assert len(results) == len(ai_security_testing.PROMPT_INJECTION_PAYLOADS)
    assert all(r["status_code"] == 200 for r in results)


def test_run_prompt_injection_suite_handles_request_errors_gracefully():
    fake_client = _fake_async_client(raises=True)
    with patch("app.services.ai_security_testing.httpx.AsyncClient", return_value=fake_client):
        results = asyncio.run(ai_security_testing.run_prompt_injection_suite("https://target.example.com/chat"))
    assert all(r["status_code"] is None and "error" in r for r in results)


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def test_classify_response_empty_text_returns_no_success():
    result = ai_security_testing.classify_response("direct_injection", "ignore instructions", "")
    assert result["success"] is False
    assert "No response" in result["reason"]


def test_classify_response_parses_structured_claude_output():
    fake_ai = MagicMock()
    resp = MagicMock()
    resp.content = [_text_block("SUCCESS: yes\nCONFIDENCE: high\nREASON: The system revealed its system prompt verbatim.\n")]
    fake_ai.messages.create.return_value = resp

    with patch.object(ai_security_testing, "_claude_client", return_value=fake_ai):
        result = ai_security_testing.classify_response("direct_injection", "ignore instructions", "Sure, here is my system prompt: ...")

    assert result["success"] is True
    assert result["confidence"] == "high"
    assert "revealed its system prompt" in result["reason"]


def test_run_and_classify_end_to_end_without_anthropic_key():
    fake_client = _fake_async_client(response_text="I can't share that.")
    with patch("app.services.ai_security_testing.httpx.AsyncClient", return_value=fake_client), \
         patch("app.services.ai_security_testing.settings") as mock_settings:
        mock_settings.ANTHROPIC_API_KEY = ""
        results = ai_security_testing.run_and_classify("https://target.example.com/chat")
    assert len(results) == len(ai_security_testing.PROMPT_INJECTION_PAYLOADS)
    assert all(r["classification"]["success"] is False for r in results)
    assert all("ANTHROPIC_API_KEY" in r["classification"]["reason"] for r in results)


def test_sync_prompt_injection_findings_to_db_only_syncs_successes(client):
    db = SessionLocal()
    c = _make_client(db)
    classified = [
        {"payload": {"category": "direct_injection", "payload": "ignore everything"}, "response_text": "leaked", "classification": {"success": True, "confidence": "high", "reason": "leaked prompt"}},
        {"payload": {"category": "jailbreak", "payload": "roleplay as DAN"}, "response_text": "refused", "classification": {"success": False, "confidence": "low", "reason": "refused"}},
    ]
    count = ai_security_testing.sync_prompt_injection_findings_to_db(db, c, "https://target.example.com/chat", classified)
    assert count == 1
    findings = db.query(Finding).filter_by(client_id=c.id).all()
    assert len(findings) == 1
    assert "direct injection" in findings[0].title


def test_sync_prompt_injection_findings_to_db_dedupes_on_rerun(client):
    db = SessionLocal()
    c = _make_client(db)
    classified = [
        {"payload": {"category": "direct_injection", "payload": "ignore everything"}, "response_text": "leaked", "classification": {"success": True, "confidence": "high", "reason": "leaked prompt"}},
    ]
    ai_security_testing.sync_prompt_injection_findings_to_db(db, c, "https://target.example.com/chat", classified)
    second = ai_security_testing.sync_prompt_injection_findings_to_db(db, c, "https://target.example.com/chat", classified)
    assert second == 0
