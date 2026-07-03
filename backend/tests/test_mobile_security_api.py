import io
import json
import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.models.models import Client, MobileAppScan, MobileScanStatus


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Mobile Co", root_domain="mobile.example.com", contact_email="a@mobile.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def test_upload_app_rejects_disallowed_extension(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/mobile-scans", headers=admin_user["headers"],
                     files={"file": ("app.exe", io.BytesIO(b"data"), "application/octet-stream")})
    assert r.status_code == 422


def test_upload_apk_creates_queued_scan(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/mobile-scans", headers=admin_user["headers"],
                     files={"file": ("app.apk", io.BytesIO(b"fake apk bytes"), "application/vnd.android.package-archive")})
    assert r.status_code == 201
    body = r.json()
    assert body["platform"] == "android"
    assert body["status"] == "queued"


def test_analyze_scan_uses_run_static_analysis_and_sets_completed(admin_user, client):
    client_id = _seed_client()
    scan_id = client.post(f"/api/clients/{client_id}/mobile-scans", headers=admin_user["headers"],
                           files={"file": ("app.apk", io.BytesIO(b"data"), "application/vnd.android.package-archive")}).json()["id"]

    fake_result = {
        "analysis": {"package_name": "com.example.app"},
        "findings": [{"masvs_control": "MSTG-AUTH-1", "control_label": "no secrets", "severity": "critical", "description": "leaked key", "status": "open"}],
        "masvs_score": 83,
    }
    with patch("app.api.mobile_security.run_static_analysis", return_value=fake_result), \
         patch("app.api.mobile_security.generate_executive_summary", return_value="Solid app overall, fix the leaked key."):
        r = client.post(f"/api/clients/{client_id}/mobile-scans/{scan_id}/analyze", headers=admin_user["headers"])

    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["masvs_score"] == 83
    assert body["app_label"] == "com.example.app"
    assert len(body["findings"]) == 1
    assert "leaked key" in body["executive_summary"]

    db = SessionLocal()
    scan = db.query(MobileAppScan).get(scan_id)
    assert scan.status == MobileScanStatus.completed
    db.close()


def test_analyze_scan_marks_failed_on_exception(admin_user, client):
    client_id = _seed_client()
    scan_id = client.post(f"/api/clients/{client_id}/mobile-scans", headers=admin_user["headers"],
                           files={"file": ("app.apk", io.BytesIO(b"data"), "application/vnd.android.package-archive")}).json()["id"]

    with patch("app.api.mobile_security.run_static_analysis", side_effect=ValueError("corrupt APK")):
        r = client.post(f"/api/clients/{client_id}/mobile-scans/{scan_id}/analyze", headers=admin_user["headers"])

    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "failed"
    assert "corrupt APK" in body["error_message"]


def test_traffic_import_parses_uploaded_har(admin_user, client):
    client_id = _seed_client()
    scan_id = client.post(f"/api/clients/{client_id}/mobile-scans", headers=admin_user["headers"],
                           files={"file": ("app.apk", io.BytesIO(b"data"), "application/vnd.android.package-archive")}).json()["id"]

    har = {"log": {"entries": [{
        "request": {"method": "GET", "url": "https://api.example.com/v1/ping", "headers": [], "postData": {}},
        "response": {"status": 200, "headers": [], "content": {"text": ""}},
    }]}}
    r = client.post(f"/api/clients/{client_id}/mobile-scans/{scan_id}/traffic-import", headers=admin_user["headers"],
                     files={"file": ("capture.har", io.BytesIO(json.dumps(har).encode()), "application/json")})
    assert r.status_code == 201
    body = r.json()
    assert len(body["discovered_endpoints"]) == 1

    r = client.get(f"/api/clients/{client_id}/mobile-scans/{scan_id}/traffic-imports", headers=admin_user["headers"])
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_traffic_import_rejects_malformed_har(admin_user, client):
    client_id = _seed_client()
    scan_id = client.post(f"/api/clients/{client_id}/mobile-scans", headers=admin_user["headers"],
                           files={"file": ("app.apk", io.BytesIO(b"data"), "application/vnd.android.package-archive")}).json()["id"]
    r = client.post(f"/api/clients/{client_id}/mobile-scans/{scan_id}/traffic-import", headers=admin_user["headers"],
                     files={"file": ("bad.har", io.BytesIO(b"not json at all"), "application/json")})
    assert r.status_code == 422
