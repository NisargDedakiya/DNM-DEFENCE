import uuid
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import Client


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Vish Co", root_domain="vish.example.com", contact_email="a@vish.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def _fake_claude_response(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    return resp


def test_create_engagement_and_analyze_with_manual_transcript(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/vishing-engagements", headers=admin_user["headers"],
                     json={"scenario": "IT helpdesk pretext", "transcript": "Hi, this is IT, please confirm your password."})
    assert r.status_code == 201
    engagement_id = r.json()["id"]

    fake_ai = MagicMock()
    fake_ai.messages.create.return_value = _fake_claude_response(
        "TECHNIQUES: authority impersonation\nDISCLOSURES: password\nRISK: critical\nSUMMARY: Employee was tricked into revealing a password.\n"
    )
    with patch("app.services.vishing._claude_client", return_value=fake_ai):
        r = client.post(f"/api/clients/{client_id}/vishing-engagements/{engagement_id}/analyze", headers=admin_user["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["risk_rating"] == "critical"
    assert body["analysis"]["disclosures"] == ["password"]


def test_upload_recording_rejects_disallowed_extension(admin_user, client):
    import io
    client_id = _seed_client()
    engagement_id = client.post(f"/api/clients/{client_id}/vishing-engagements", headers=admin_user["headers"],
                                 json={"scenario": "test"}).json()["id"]
    r = client.post(f"/api/clients/{client_id}/vishing-engagements/{engagement_id}/recording",
                     headers=admin_user["headers"],
                     files={"file": ("call.exe", io.BytesIO(b"data"), "application/octet-stream")})
    assert r.status_code == 422


def test_upload_recording_accepts_audio_file(admin_user, client):
    import io
    client_id = _seed_client()
    engagement_id = client.post(f"/api/clients/{client_id}/vishing-engagements", headers=admin_user["headers"],
                                 json={"scenario": "test"}).json()["id"]
    r = client.post(f"/api/clients/{client_id}/vishing-engagements/{engagement_id}/recording",
                     headers=admin_user["headers"],
                     files={"file": ("call.mp3", io.BytesIO(b"fake audio bytes"), "audio/mpeg")})
    assert r.status_code == 200
