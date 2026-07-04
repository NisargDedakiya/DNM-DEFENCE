import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.models.models import Client, User, UserRole


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Red Team Co", root_domain="redteam-api.example.com",
               contact_email="a@redteam-api.example.com")
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


def _create_operation(client, client_id, headers):
    return client.post(f"/api/clients/{client_id}/red-team/operations", headers=headers,
                        json={"name": "Op Nightfall", "objective": "Test detection", "threat_actor": "FIN7"}).json()


def test_client_role_cannot_list_operations(admin_user, client):
    client_id = _seed_client()
    headers = _client_role_headers(client_id)
    r = client.get(f"/api/clients/{client_id}/red-team/operations", headers=headers)
    assert r.status_code == 403


def test_client_role_cannot_create_operation(admin_user, client):
    client_id = _seed_client()
    headers = _client_role_headers(client_id)
    r = client.post(f"/api/clients/{client_id}/red-team/operations", headers=headers,
                     json={"name": "Op Nightfall"})
    assert r.status_code == 403


def test_client_role_cannot_get_narrative(admin_user, client):
    client_id = _seed_client()
    op = _create_operation(client, client_id, admin_user["headers"])
    headers = _client_role_headers(client_id)
    r = client.get(f"/api/clients/{client_id}/red-team/operations/{op['id']}/narrative", headers=headers)
    assert r.status_code == 403


def test_staff_can_create_and_list_operations(admin_user, client):
    client_id = _seed_client()
    op = _create_operation(client, client_id, admin_user["headers"])
    assert op["name"] == "Op Nightfall"
    assert op["status"] == "planning"

    r = client.get(f"/api/clients/{client_id}/red-team/operations", headers=admin_user["headers"])
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_operation_update_and_delete(admin_user, client):
    client_id = _seed_client()
    op = _create_operation(client, client_id, admin_user["headers"])

    r = client.patch(f"/api/clients/{client_id}/red-team/operations/{op['id']}", headers=admin_user["headers"],
                      json={"status": "active", "roe_signed": True})
    assert r.status_code == 200
    assert r.json()["status"] == "active"
    assert r.json()["roe_signed"] is True

    r = client.delete(f"/api/clients/{client_id}/red-team/operations/{op['id']}", headers=admin_user["headers"])
    assert r.status_code == 204


def test_timeline_entry_crud_and_heatmap(admin_user, client):
    client_id = _seed_client()
    op = _create_operation(client, client_id, admin_user["headers"])

    r = client.post(f"/api/clients/{client_id}/red-team/operations/{op['id']}/timeline", headers=admin_user["headers"],
                     json={"timestamp": "2026-01-01T10:00:00", "phase": "initial_access",
                           "action": "Phished the helpdesk", "attack_technique_id": "T1566.001",
                           "detected": "not_detected"})
    assert r.status_code == 201
    entry_id = r.json()["id"]

    r = client.get(f"/api/clients/{client_id}/red-team/operations/{op['id']}/timeline", headers=admin_user["headers"])
    assert len(r.json()) == 1
    assert r.json()[0]["id"] == entry_id

    r = client.get(f"/api/clients/{client_id}/red-team/operations/{op['id']}/heatmap", headers=admin_user["headers"])
    assert r.status_code == 200
    scores = {t["techniqueID"]: t["score"] for t in r.json()["techniques"]}
    assert scores == {"T1566.001": 1}


def test_implant_crud(admin_user, client):
    client_id = _seed_client()
    op = _create_operation(client, client_id, admin_user["headers"])

    r = client.post(f"/api/clients/{client_id}/red-team/operations/{op['id']}/implants", headers=admin_user["headers"],
                     json={"host": "ws-01", "ip_address": "10.0.0.5", "implant_type": "beacon"})
    assert r.status_code == 201
    implant_id = r.json()["id"]
    assert r.json()["is_active"] is True

    r = client.patch(f"/api/clients/{client_id}/red-team/operations/{op['id']}/implants/{implant_id}",
                      headers=admin_user["headers"], json={"is_active": False})
    assert r.status_code == 200
    assert r.json()["is_active"] is False

    r = client.get(f"/api/clients/{client_id}/red-team/operations/{op['id']}/implants", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_infrastructure_crud_and_exposure_check(admin_user, client):
    client_id = _seed_client()
    op = _create_operation(client, client_id, admin_user["headers"])

    r = client.post(f"/api/clients/{client_id}/red-team/operations/{op['id']}/infrastructure",
                     headers=admin_user["headers"],
                     json={"infra_type": "c2_server", "identifier": "1.2.3.4", "provider": "DigitalOcean"})
    assert r.status_code == 201

    r = client.get(f"/api/clients/{client_id}/red-team/operations/{op['id']}/infrastructure", headers=admin_user["headers"])
    assert len(r.json()) == 1

    with patch("app.api.red_team.check_c2_infra_exposure", return_value=[{"ip": "1.2.3.4", "org": "flagged"}]) as mock_check:
        r = client.get(f"/api/clients/{client_id}/red-team/operations/{op['id']}/infrastructure/exposure-check",
                        headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["exposure"] == [{"ip": "1.2.3.4", "org": "flagged"}]
    mock_check.assert_called_once()


def test_narrative_and_purple_team_export(admin_user, client):
    client_id = _seed_client()
    op = _create_operation(client, client_id, admin_user["headers"])
    client.post(f"/api/clients/{client_id}/red-team/operations/{op['id']}/timeline", headers=admin_user["headers"],
                json={"timestamp": "2026-01-01T10:00:00", "phase": "recon", "action": "Passive OSINT recon"})

    with patch("app.api.red_team.generate_attack_narrative", return_value="Narrative text.") as mock_narrative:
        r = client.get(f"/api/clients/{client_id}/red-team/operations/{op['id']}/narrative", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.text == "Narrative text."
    mock_narrative.assert_called_once()

    r = client.get(f"/api/clients/{client_id}/red-team/operations/{op['id']}/purple-team-export",
                    headers=admin_user["headers"])
    assert r.status_code == 200
    assert "Passive OSINT recon" in r.text


def test_operation_not_found_returns_404(admin_user, client):
    client_id = _seed_client()
    r = client.get(f"/api/clients/{client_id}/red-team/operations/{uuid.uuid4()}", headers=admin_user["headers"])
    assert r.status_code == 404
