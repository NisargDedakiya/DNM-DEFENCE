import io
import json
import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.models.models import Client, User, UserRole


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="DFIR Co", root_domain="dfir-api.example.com",
               contact_email="a@dfir-api.example.com")
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


def _create_case(client, client_id, headers, case_number="DFIR-2026-0001"):
    return client.post(f"/api/clients/{client_id}/dfir/cases", headers=headers,
                        json={"case_number": case_number, "incident_type": "Ransomware", "severity": "critical"}).json()


def test_client_role_cannot_list_cases(admin_user, client):
    client_id = _seed_client()
    headers = _client_role_headers(client_id)
    r = client.get(f"/api/clients/{client_id}/dfir/cases", headers=headers)
    assert r.status_code == 403


def test_client_role_cannot_create_case(admin_user, client):
    client_id = _seed_client()
    headers = _client_role_headers(client_id)
    r = client.post(f"/api/clients/{client_id}/dfir/cases", headers=headers, json={"case_number": "DFIR-2026-0099"})
    assert r.status_code == 403


def test_client_role_cannot_get_technical_report(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])
    headers = _client_role_headers(client_id)
    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/reports/technical", headers=headers)
    assert r.status_code == 403


def test_staff_can_create_and_list_cases(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])
    assert case["case_number"] == "DFIR-2026-0001"
    assert case["status"] == "active"

    r = client.get(f"/api/clients/{client_id}/dfir/cases", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_duplicate_case_number_rejected(admin_user, client):
    client_id = _seed_client()
    _create_case(client, client_id, admin_user["headers"])
    r = client.post(f"/api/clients/{client_id}/dfir/cases", headers=admin_user["headers"],
                     json={"case_number": "DFIR-2026-0001"})
    assert r.status_code == 422


def test_case_update(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])
    r = client.patch(f"/api/clients/{client_id}/dfir/cases/{case['id']}", headers=admin_user["headers"],
                      json={"status": "contained", "data_exfiltrated": True})
    assert r.status_code == 200
    assert r.json()["status"] == "contained"
    assert r.json()["data_exfiltrated"] is True


def test_evidence_upload_computes_hashes_and_custody(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])
    file_bytes = b"forensic disk image bytes"

    r = client.post(f"/api/clients/{client_id}/dfir/cases/{case['id']}/evidence", headers=admin_user["headers"],
                     data={"evidence_type": "disk image", "source_host": "fs01", "acquisition_tool": "FTK Imager",
                           "acquired_by_name": "analyst1"},
                     files={"file": ("disk.img", io.BytesIO(file_bytes), "application/octet-stream")})
    assert r.status_code == 201
    evidence = r.json()
    import hashlib
    assert evidence["sha256_hash"] == hashlib.sha256(file_bytes).hexdigest()
    assert len(evidence["chain_of_custody"]) == 1

    r = client.post(f"/api/clients/{client_id}/dfir/cases/{case['id']}/evidence/{evidence['id']}/custody",
                     headers=admin_user["headers"], json={"custodian": "analyst2", "action": "transferred to lab"})
    assert r.status_code == 200
    assert len(r.json()["chain_of_custody"]) == 2

    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/evidence", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_ioc_crud_and_exports(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])
    r = client.post(f"/api/clients/{client_id}/dfir/cases/{case['id']}/iocs", headers=admin_user["headers"],
                     json={"ioc_type": "ip", "value": "1.2.3.4", "confidence": "high"})
    assert r.status_code == 201

    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/iocs", headers=admin_user["headers"])
    assert len(r.json()) == 1

    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/iocs/export/stix", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["type"] == "bundle"

    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/iocs/export/sigma", headers=admin_user["headers"])
    assert r.status_code == 200
    assert "1.2.3.4" in r.text

    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/iocs/export/csv", headers=admin_user["headers"])
    assert r.status_code == 200
    assert "1.2.3.4" in r.text


def test_timeline_crud(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])
    r = client.post(f"/api/clients/{client_id}/dfir/cases/{case['id']}/timeline", headers=admin_user["headers"],
                     json={"timestamp": "2026-01-01T00:00:00", "event_description": "Initial compromise", "host": "fs01"})
    assert r.status_code == 201

    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/timeline", headers=admin_user["headers"])
    assert len(r.json()) == 1
    assert r.json()[0]["event_description"] == "Initial compromise"


def test_reports_endpoints(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])

    with patch("app.api.dfir.generate_executive_report", return_value="Exec summary.") as mock_exec:
        r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/reports/executive", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.text == "Exec summary."
    mock_exec.assert_called_once()

    with patch("app.api.dfir.generate_technical_report", return_value="Tech report.") as mock_tech:
        r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/reports/technical", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.text == "Tech report."
    mock_tech.assert_called_once()


def test_retainer_upsert_and_get(admin_user, client):
    client_id = _seed_client()
    r = client.get(f"/api/clients/{client_id}/dfir/retainer", headers=admin_user["headers"])
    assert r.status_code == 404

    r = client.put(f"/api/clients/{client_id}/dfir/retainer", headers=admin_user["headers"],
                    json={"tier": "Gold", "hours_included_per_year": 40, "response_sla_hours": 4})
    assert r.status_code == 200
    assert r.json()["tier"] == "Gold"

    r = client.get(f"/api/clients/{client_id}/dfir/retainer", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["hours_included_per_year"] == 40


def test_log_analysis_upload_cloudtrail(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])
    payload = {"Records": [
        {"eventTime": "2026-01-01T00:00:00Z", "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
         "sourceIPAddress": "1.2.3.4", "userIdentity": {"userName": "alice"}, "errorCode": "Failed authentication"},
    ]}
    with patch("app.api.dfir.generate_log_narrative", return_value="Narrative body."):
        r = client.post(f"/api/clients/{client_id}/dfir/cases/{case['id']}/log-analysis/upload",
                         headers=admin_user["headers"], data={"log_type": "cloudtrail"},
                         files={"file": ("trail.json", io.BytesIO(json.dumps(payload).encode()), "application/json")})
    assert r.status_code == 201
    job = r.json()
    assert job["events_count"] == 1
    assert job["narrative"] == "Narrative body."

    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/log-analysis/{job['id']}/results",
                    headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["events_count"] == 1

    r = client.get(f"/api/clients/{client_id}/dfir/cases/{case['id']}/log-analysis", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_log_analysis_upload_rejects_unknown_log_type(admin_user, client):
    client_id = _seed_client()
    case = _create_case(client, client_id, admin_user["headers"])
    r = client.post(f"/api/clients/{client_id}/dfir/cases/{case['id']}/log-analysis/upload",
                     headers=admin_user["headers"], data={"log_type": "not_a_real_type"},
                     files={"file": ("x.log", io.BytesIO(b"data"), "text/plain")})
    assert r.status_code == 422


def test_case_not_found_returns_404(admin_user, client):
    client_id = _seed_client()
    r = client.get(f"/api/clients/{client_id}/dfir/cases/{uuid.uuid4()}", headers=admin_user["headers"])
    assert r.status_code == 404
