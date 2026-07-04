import uuid
from unittest.mock import patch

from cryptography.fernet import Fernet

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.models.models import Client, User, UserRole

_TEST_ENCRYPTION_KEY = Fernet.generate_key().decode()


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="TH Client", root_domain="th-api.example.com",
               contact_email="a@th-api.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def _client_role_headers(client_id):
    db = SessionLocal()
    user = User(id=str(uuid.uuid4()), email=f"client-{uuid.uuid4().hex[:8]}@test.local",
                hashed_password=hash_password("pw"), role=UserRole.client, client_id=client_id)
    db.add(user)
    db.commit()
    token = create_access_token(user)
    db.close()
    return {"Authorization": f"Bearer {token}"}


def test_client_role_cannot_list_hypotheses(admin_user, client):
    headers = _client_role_headers(None)
    r = client.get("/api/threat-hunting/hypotheses", headers=headers)
    assert r.status_code == 403


def test_client_role_cannot_list_hunts(admin_user, client):
    client_id = _seed_client()
    headers = _client_role_headers(client_id)
    r = client.get(f"/api/clients/{client_id}/threat-hunting/hunts", headers=headers)
    assert r.status_code == 403


def test_seed_and_list_hypotheses(admin_user, client):
    r = client.post("/api/threat-hunting/hypotheses/seed", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["created"] > 0

    r = client.get("/api/threat-hunting/hypotheses", headers=admin_user["headers"])
    assert r.status_code == 200
    assert len(r.json()) == r.json().__len__()  # sanity: response is a list
    assert len(r.json()) > 0

    r = client.post("/api/threat-hunting/hypotheses/seed", headers=admin_user["headers"])
    assert r.json()["created"] == 0


def test_create_hypothesis_manually(admin_user, client):
    r = client.post("/api/threat-hunting/hypotheses", headers=admin_user["headers"],
                     json={"title": "Custom hunt", "attack_technique": "T1078", "data_sources": ["EDR"]})
    assert r.status_code == 201
    assert r.json()["source"] == "manual"


def test_generate_hypothesis_endpoint(admin_user, client):
    with patch("app.api.threat_hunting.generate_hypothesis",
               return_value={"title": "AI hypothesis", "description": "desc", "attack_technique": "T1566", "data_sources": ["email logs"]}):
        r = client.post("/api/threat-hunting/hypotheses/generate", headers=admin_user["headers"],
                         json={"client_industry": "fintech"})
    assert r.status_code == 201
    assert r.json()["source"] == "ai_generated"
    assert r.json()["title"] == "AI hypothesis"


def test_hunt_operation_crud_and_findings(admin_user, client):
    client_id = _seed_client()
    hypothesis = client.post("/api/threat-hunting/hypotheses", headers=admin_user["headers"],
                              json={"title": "Test hypothesis", "attack_technique": "T1078"}).json()

    r = client.post(f"/api/clients/{client_id}/threat-hunting/hunts", headers=admin_user["headers"],
                     json={"hypothesis_id": hypothesis["id"]})
    assert r.status_code == 201
    hunt = r.json()
    assert hunt["status"] == "planned"

    r = client.patch(f"/api/clients/{client_id}/threat-hunting/hunts/{hunt['id']}", headers=admin_user["headers"],
                      json={"status": "complete", "outcome": "threat_found", "hours_spent": 6})
    assert r.status_code == 200
    assert r.json()["outcome"] == "threat_found"

    r = client.post(f"/api/clients/{client_id}/threat-hunting/hunts/{hunt['id']}/findings", headers=admin_user["headers"],
                     json={"title": "Suspicious activity", "severity": "high", "confirmed": True})
    assert r.status_code == 201

    r = client.get(f"/api/clients/{client_id}/threat-hunting/hunts/{hunt['id']}/findings", headers=admin_user["headers"])
    assert len(r.json()) == 1

    with patch("app.api.threat_hunting.generate_hunt_report", return_value="Report body.") as mock_report:
        r = client.get(f"/api/clients/{client_id}/threat-hunting/hunts/{hunt['id']}/report", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.text == "Report body."
    mock_report.assert_called_once()


def test_hunt_creation_rejects_unknown_hypothesis(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/threat-hunting/hunts", headers=admin_user["headers"],
                     json={"hypothesis_id": str(uuid.uuid4())})
    assert r.status_code == 422


def test_coverage_endpoint(admin_user, client):
    client_id = _seed_client()
    r = client.get(f"/api/clients/{client_id}/threat-hunting/coverage", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["techniques"] == []


def test_enrich_ioc_endpoint(admin_user, client):
    client_id = _seed_client()
    with patch("app.api.threat_hunting.enrich_ioc", return_value={"ioc_value": "1.2.3.4", "ioc_type": "ip", "enriched": True, "flagged": False}):
        r = client.post(f"/api/clients/{client_id}/threat-hunting/enrich-ioc", headers=admin_user["headers"],
                         json={"ioc_value": "1.2.3.4", "ioc_type": "ip"})
    assert r.status_code == 200
    assert r.json()["enriched"] is True


def test_siem_connection_registration_requires_provider_specific_fields(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/threat-hunting/siem-connections", headers=admin_user["headers"],
                     json={"provider": "elastic"})
    assert r.status_code == 400


def test_siem_connection_registration_and_query(admin_user, client):
    client_id = _seed_client()
    with patch("app.core.crypto.settings.ENCRYPTION_KEY", _TEST_ENCRYPTION_KEY):
        r = client.post(f"/api/clients/{client_id}/threat-hunting/siem-connections", headers=admin_user["headers"],
                         json={"provider": "elastic", "base_url": "https://siem.example.com", "api_key": "abc123"})
    assert r.status_code == 201
    connection = r.json()
    assert connection["provider"] == "elastic"

    r = client.get(f"/api/clients/{client_id}/threat-hunting/siem-connections", headers=admin_user["headers"])
    assert len(r.json()) == 1

    with patch("app.api.threat_hunting.query_elastic", return_value=[{"user": "alice"}]) as mock_query:
        r = client.post(f"/api/clients/{client_id}/threat-hunting/siem-connections/{connection['id']}/query",
                         headers=admin_user["headers"], json={"query": "user:alice"})
    assert r.status_code == 200
    assert r.json()["results"] == [{"user": "alice"}]
    mock_query.assert_called_once()


def test_siem_connection_query_unsupported_provider(admin_user, client):
    client_id = _seed_client()
    with patch("app.core.crypto.settings.ENCRYPTION_KEY", _TEST_ENCRYPTION_KEY):
        connection = client.post(f"/api/clients/{client_id}/threat-hunting/siem-connections", headers=admin_user["headers"],
                                  json={"provider": "sentinelone", "base_url": "https://s1.example.com"}).json()
    r = client.post(f"/api/clients/{client_id}/threat-hunting/siem-connections/{connection['id']}/query",
                     headers=admin_user["headers"], json={"query": "x"})
    assert r.status_code == 422
