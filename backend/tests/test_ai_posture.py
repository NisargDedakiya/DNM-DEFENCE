from unittest.mock import MagicMock, patch

from app.services import ai_posture


def test_check_ai_library_cves_returns_hits_when_version_in_summary():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": [{"id": "CVE-2024-9999", "summary": "langchain 0.1.0 has a vulnerability", "cvss": 7.5}]}
    with patch("app.services.ai_posture.httpx.get", return_value=resp):
        hits = ai_posture.check_ai_library_cves({"langchain": "0.1.0"})
    assert len(hits) == 1
    assert hits[0]["cve_id"] == "CVE-2024-9999"


def test_check_ai_library_cves_skips_non_matching_version():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": [{"id": "CVE-2024-9999", "summary": "langchain 0.2.0 has a vulnerability", "cvss": 7.5}]}
    with patch("app.services.ai_posture.httpx.get", return_value=resp):
        hits = ai_posture.check_ai_library_cves({"langchain": "0.1.0"})
    assert hits == []


def test_check_ai_library_cves_handles_empty_input():
    with patch("app.services.ai_posture.httpx.get") as mock_get:
        hits = ai_posture.check_ai_library_cves({})
    mock_get.assert_not_called()
    assert hits == []


def test_check_ai_library_cves_degrades_gracefully_on_error():
    import httpx as httpx_module
    with patch("app.services.ai_posture.httpx.get", side_effect=httpx_module.ConnectError("down")):
        hits = ai_posture.check_ai_library_cves({"tensorflow": "2.13.0"})
    assert hits == []


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def test_generate_ai_security_brief_grounds_prompt_in_real_data():
    fake_ai = MagicMock()
    resp = MagicMock()
    resp.content = [_text_block("Overall posture is solid.")]
    fake_ai.messages.create.return_value = resp

    cve_hits = [{"library": "langchain", "version": "0.1.0", "cve_id": "CVE-2024-9999", "summary": "s", "cvss": 7.5}]
    owasp_summary = {"percent_implemented": 40, "implemented": 4, "total": 10}

    with patch.object(ai_posture, "_claude_client", return_value=fake_ai):
        result = ai_posture.generate_ai_security_brief("Acme Co", 3, cve_hits, owasp_summary)

    assert result == "Overall posture is solid."
    prompt = fake_ai.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "CVE-2024-9999" in prompt
    assert "40% implemented" in prompt
    assert "do not invent" in prompt.lower()
