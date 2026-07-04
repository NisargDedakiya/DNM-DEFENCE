import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.models.models import Client, User, UserRole


def _client_role_headers(client_id=None):
    db = SessionLocal()
    user = User(id=str(uuid.uuid4()), email=f"client-{uuid.uuid4().hex[:8]}@test.local",
                hashed_password=hash_password("pw"), role=UserRole.client, client_id=client_id)
    db.add(user)
    db.commit()
    token = create_access_token(user)
    db.close()
    return {"Authorization": f"Bearer {token}"}


def _create_target(client, headers, **overrides):
    payload = {"name": "libfoo", "vendor": "Foo Corp", "version": "2.1.0"}
    payload.update(overrides)
    return client.post("/api/zero-day/targets", headers=headers, json=payload).json()


def test_client_role_cannot_list_targets(admin_user, client):
    headers = _client_role_headers()
    r = client.get("/api/zero-day/targets", headers=headers)
    assert r.status_code == 403


def test_client_role_cannot_create_target(admin_user, client):
    headers = _client_role_headers()
    r = client.post("/api/zero-day/targets", headers=headers, json={"name": "libfoo"})
    assert r.status_code == 403


def test_staff_can_create_independent_target(admin_user, client):
    target = _create_target(client, admin_user["headers"])
    assert target["name"] == "libfoo"
    assert target["client_id"] is None
    assert target["status"] == "identified"


def test_staff_can_create_client_commissioned_target(admin_user, client):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="ZD Client", root_domain="zd.example.com", contact_email="a@zd.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()

    target = _create_target(client, admin_user["headers"], client_id=cid)
    assert target["client_id"] == cid


def test_target_update_and_delete(admin_user, client):
    target = _create_target(client, admin_user["headers"])
    r = client.patch(f"/api/zero-day/targets/{target['id']}", headers=admin_user["headers"],
                      json={"status": "active", "total_hours": 12})
    assert r.status_code == 200
    assert r.json()["status"] == "active"
    assert r.json()["total_hours"] == 12

    r = client.delete(f"/api/zero-day/targets/{target['id']}", headers=admin_user["headers"])
    assert r.status_code == 204


def test_finding_crud_and_deadline_field(admin_user, client):
    target = _create_target(client, admin_user["headers"])
    r = client.post(f"/api/zero-day/targets/{target['id']}/findings", headers=admin_user["headers"],
                     json={"title": "Heap overflow", "vuln_class": "Heap Buffer Overflow", "severity": "critical"})
    assert r.status_code == 201
    finding = r.json()
    assert finding["days_until_deadline"] is None

    r = client.patch(f"/api/zero-day/targets/{target['id']}/findings/{finding['id']}", headers=admin_user["headers"],
                      json={"vendor_notified": "2026-06-01T00:00:00"})
    assert r.status_code == 200
    assert r.json()["days_until_deadline"] is not None

    r = client.get(f"/api/zero-day/targets/{target['id']}/findings", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_lookup_cve_endpoint(admin_user, client):
    target = _create_target(client, admin_user["headers"])
    finding = client.post(f"/api/zero-day/targets/{target['id']}/findings", headers=admin_user["headers"],
                           json={"title": "RCE", "cve_id": "CVE-2021-44228"}).json()

    with patch("app.api.zero_day.check_cve_exists", return_value=True), \
         patch("app.api.zero_day.lookup_cve", return_value={"cve_id": "CVE-2021-44228", "cvss_score": 10.0}):
        r = client.get(f"/api/zero-day/findings/{finding['id']}/lookup-cve", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["exists"] is True
    assert r.json()["detail"]["cvss_score"] == 10.0


def test_lookup_cve_endpoint_requires_cve_id(admin_user, client):
    target = _create_target(client, admin_user["headers"])
    finding = client.post(f"/api/zero-day/targets/{target['id']}/findings", headers=admin_user["headers"],
                           json={"title": "No CVE yet"}).json()
    r = client.get(f"/api/zero-day/findings/{finding['id']}/lookup-cve", headers=admin_user["headers"])
    assert r.status_code == 422


def test_advisory_endpoint(admin_user, client):
    target = _create_target(client, admin_user["headers"])
    finding = client.post(f"/api/zero-day/targets/{target['id']}/findings", headers=admin_user["headers"],
                           json={"title": "RCE"}).json()

    with patch("app.api.zero_day.generate_disclosure_advisory", return_value="Advisory text.") as mock_gen:
        r = client.get(f"/api/zero-day/findings/{finding['id']}/advisory", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.text == "Advisory text."
    mock_gen.assert_called_once()


def test_hackerone_submit_returns_422_when_not_configured(admin_user, client):
    target = _create_target(client, admin_user["headers"])
    finding = client.post(f"/api/zero-day/targets/{target['id']}/findings", headers=admin_user["headers"],
                           json={"title": "RCE"}).json()
    with patch("app.api.zero_day.submit_to_hackerone", return_value=None):
        r = client.post(f"/api/zero-day/findings/{finding['id']}/submit/hackerone", headers=admin_user["headers"],
                         json={"program_handle": "acme", "api_identifier": "id"})
    assert r.status_code == 422


def test_fuzzing_job_crud(admin_user, client):
    target = _create_target(client, admin_user["headers"])
    r = client.post(f"/api/zero-day/targets/{target['id']}/fuzzing-jobs", headers=admin_user["headers"],
                     json={"fuzzer": "afl++", "target_binary_path": "/bin/target"})
    assert r.status_code == 201
    job_id = r.json()["id"]
    assert r.json()["status"] == "queued"

    r = client.patch(f"/api/zero-day/targets/{target['id']}/fuzzing-jobs/{job_id}", headers=admin_user["headers"],
                      json={"status": "running", "crashes_found": 3})
    assert r.status_code == 200
    assert r.json()["crashes_found"] == 3

    r = client.get(f"/api/zero-day/targets/{target['id']}/fuzzing-jobs", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_target_not_found_returns_404(admin_user, client):
    r = client.get(f"/api/zero-day/targets/{uuid.uuid4()}", headers=admin_user["headers"])
    assert r.status_code == 404
