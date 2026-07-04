import io
import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.models.models import Client, User, UserRole


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="IoT Co", root_domain="iot-api.example.com",
               contact_email="a@iot-api.example.com")
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


def _upload_firmware(client, client_id, headers):
    return client.post(f"/api/clients/{client_id}/firmware-scans", headers=headers,
                        files={"file": ("firmware.bin", io.BytesIO(b"BusyBox v1.31.1 dummy firmware"), "application/octet-stream")}).json()


def test_client_role_cannot_list_scans(admin_user, client):
    client_id = _seed_client()
    headers = _client_role_headers(client_id)
    r = client.get(f"/api/clients/{client_id}/firmware-scans", headers=headers)
    assert r.status_code == 403


def test_client_role_cannot_upload_firmware(admin_user, client):
    client_id = _seed_client()
    headers = _client_role_headers(client_id)
    r = client.post(f"/api/clients/{client_id}/firmware-scans", headers=headers,
                     files={"file": ("firmware.bin", io.BytesIO(b"data"), "application/octet-stream")})
    assert r.status_code == 403


def test_staff_can_upload_and_list_scans(admin_user, client):
    client_id = _seed_client()
    scan = _upload_firmware(client, client_id, admin_user["headers"])
    assert scan["status"] == "queued"
    assert scan["original_filename"] == "firmware.bin"

    r = client.get(f"/api/clients/{client_id}/firmware-scans", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_analyze_scan_extraction_unavailable_falls_back_to_raw_scan(admin_user, client):
    client_id = _seed_client()
    scan = _upload_firmware(client, client_id, admin_user["headers"])

    with patch("app.api.firmware.run_binwalk_extraction", return_value={"extracted": False, "output_dir": None, "raw_output": None}), \
         patch("app.api.firmware.check_library_cves", return_value=[]), \
         patch("app.api.firmware.generate_firmware_summary", return_value="Summary body."):
        r = client.post(f"/api/clients/{client_id}/firmware-scans/{scan['id']}/analyze", headers=admin_user["headers"])
    assert r.status_code == 200
    result = r.json()
    assert result["status"] == "completed"
    assert result["component_summary"]["BusyBox"] == "1.31.1"
    assert result["findings"]["extracted"] is False
    assert result["executive_summary"] == "Summary body."


def test_analyze_scan_handles_generate_summary_failure_gracefully(admin_user, client):
    client_id = _seed_client()
    scan = _upload_firmware(client, client_id, admin_user["headers"])

    with patch("app.api.firmware.run_binwalk_extraction", return_value={"extracted": False, "output_dir": None, "raw_output": None}), \
         patch("app.api.firmware.check_library_cves", return_value=[]), \
         patch("app.api.firmware.generate_firmware_summary", side_effect=RuntimeError("no API key")):
        r = client.post(f"/api/clients/{client_id}/firmware-scans/{scan['id']}/analyze", headers=admin_user["headers"])
    assert r.status_code == 200
    result = r.json()
    assert result["status"] == "completed"
    assert result["executive_summary"] is None


def test_analyze_scan_marks_failed_on_unexpected_error(admin_user, client):
    client_id = _seed_client()
    scan = _upload_firmware(client, client_id, admin_user["headers"])

    with patch("app.api.firmware.run_binwalk_extraction", side_effect=Exception("boom")):
        r = client.post(f"/api/clients/{client_id}/firmware-scans/{scan['id']}/analyze", headers=admin_user["headers"])
    assert r.status_code == 200
    result = r.json()
    assert result["status"] == "failed"
    assert "boom" in result["error_message"]


def test_scan_not_found_returns_404(admin_user, client):
    client_id = _seed_client()
    r = client.get(f"/api/clients/{client_id}/firmware-scans/{uuid.uuid4()}", headers=admin_user["headers"])
    assert r.status_code == 404
