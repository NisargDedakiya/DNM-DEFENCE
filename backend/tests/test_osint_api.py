import uuid
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import Client


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Osint API Co", root_domain="osint-api.example.com", contact_email="a@osint-api.example.com")
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


def test_generate_and_list_and_export_profile(admin_user, client):
    client_id = _seed_client()

    fake_ai = MagicMock()
    fake_ai.messages.create.return_value = _fake_claude_response("Narrative text about the target.")

    with patch("app.services.osint.subprocess.run", side_effect=FileNotFoundError()), \
         patch("app.services.osint.get_dns_records", return_value=[]), \
         patch("app.services.osint._claude_client", return_value=fake_ai):
        r = client.post(f"/api/clients/{client_id}/osint/generate", headers=admin_user["headers"],
                         json={"employee_names": ["Jane Doe"], "careers_page_url": None})
    assert r.status_code == 201
    profile_id = r.json()["id"]
    assert "Narrative text" in r.json()["findings"]["narrative"]

    r = client.get(f"/api/clients/{client_id}/osint", headers=admin_user["headers"])
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = client.get(f"/api/clients/{client_id}/osint/{profile_id}/export/pdf", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_export_pdf_404_for_unknown_profile(admin_user, client):
    client_id = _seed_client()
    r = client.get(f"/api/clients/{client_id}/osint/{uuid.uuid4()}/export/pdf", headers=admin_user["headers"])
    assert r.status_code == 404
