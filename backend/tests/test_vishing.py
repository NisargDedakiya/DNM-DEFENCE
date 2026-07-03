import uuid
from unittest.mock import MagicMock, patch

from app.models.models import VishingEngagement
from app.services import vishing


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _fake_claude_response(text):
    resp = MagicMock()
    resp.content = [_text_block(text)]
    return resp


def test_transcribe_recording_skips_without_api_key():
    with patch("app.services.vishing.settings") as mock_settings:
        mock_settings.OPENAI_API_KEY = ""
        result = vishing.transcribe_recording("/tmp/fake.mp3")
    assert result == ""


def test_analyze_transcript_returns_empty_shape_for_blank_transcript():
    result = vishing.analyze_transcript("")
    assert result["techniques_identified"] == []
    assert result["risk_rating"] is None
    assert "No transcript" in result["summary"]


def test_analyze_transcript_parses_structured_claude_response():
    fake_ai = MagicMock()
    fake_ai.messages.create.return_value = _fake_claude_response(
        "TECHNIQUES: authority impersonation, urgency\n"
        "DISCLOSURES: employee ID, internal system name\n"
        "RISK: high\n"
        "SUMMARY: The caller impersonated IT and extracted the employee ID.\n"
    )
    with patch.object(vishing, "_claude_client", return_value=fake_ai):
        result = vishing.analyze_transcript("Hi, this is IT support, I need your employee ID...", scenario="IT helpdesk pretext")

    assert result["techniques_identified"] == ["authority impersonation", "urgency"]
    assert result["disclosures"] == ["employee ID", "internal system name"]
    assert result["risk_rating"] == "high"
    assert "impersonated IT" in result["summary"]

    prompt = fake_ai.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "IT helpdesk pretext" in prompt


def test_analyze_transcript_handles_no_disclosures():
    fake_ai = MagicMock()
    fake_ai.messages.create.return_value = _fake_claude_response(
        "TECHNIQUES: none identified\nDISCLOSURES: none\nRISK: low\nSUMMARY: Employee refused to comply.\n"
    )
    with patch.object(vishing, "_claude_client", return_value=fake_ai):
        result = vishing.analyze_transcript("Some transcript text.")
    assert result["disclosures"] == []
    assert result["risk_rating"] == "low"


def test_run_vishing_analysis_uses_existing_transcript_without_transcribing():
    engagement = VishingEngagement(id=str(uuid.uuid4()), client_id=str(uuid.uuid4()),
                                    scenario="test", transcript="already have a transcript")
    with patch("app.services.vishing.transcribe_recording") as mock_transcribe, \
         patch("app.services.vishing.analyze_transcript", return_value={"techniques_identified": [], "disclosures": [],
                                                                          "risk_rating": None, "summary": "ok", "raw_response": ""}) as mock_analyze:
        vishing.run_vishing_analysis(engagement)
    mock_transcribe.assert_not_called()
    mock_analyze.assert_called_once()
