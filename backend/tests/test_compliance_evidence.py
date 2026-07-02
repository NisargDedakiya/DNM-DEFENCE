import io
import uuid

from app.core.database import SessionLocal
from app.models.models import Client, ComplianceControl, ComplianceFramework, ComplianceControlStatus


def _seed_client_with_control():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Evidence Co", root_domain="evidence.example.com", contact_email="a@evidence.example.com")
    db.add(c)
    db.commit()
    control = ComplianceControl(id=str(uuid.uuid4()), client_id=c.id, framework=ComplianceFramework.soc2,
                                 control_id="CC1.1", control_name="Test control", status=ComplianceControlStatus.in_progress)
    db.add(control)
    db.commit()
    ids = (c.id, control.id)
    db.close()
    return ids


def test_upload_evidence_sets_file_path(admin_user, client):
    client_id, control_id = _seed_client_with_control()
    fake_file = io.BytesIO(b"fake pdf content")
    r = client.post(
        f"/api/clients/{client_id}/compliance/{control_id}/evidence",
        headers=admin_user["headers"],
        files={"file": ("policy.pdf", fake_file, "application/pdf")},
    )
    assert r.status_code == 200

    db = SessionLocal()
    control = db.query(ComplianceControl).get(control_id)
    assert control.evidence_file_path is not None
    db.close()


def test_upload_evidence_rejects_disallowed_extension(admin_user, client):
    client_id, control_id = _seed_client_with_control()
    fake_file = io.BytesIO(b"#!/bin/sh\necho pwned")
    r = client.post(
        f"/api/clients/{client_id}/compliance/{control_id}/evidence",
        headers=admin_user["headers"],
        files={"file": ("evil.sh", fake_file, "application/x-sh")},
    )
    assert r.status_code == 422


def test_download_evidence_returns_uploaded_content(admin_user, client):
    client_id, control_id = _seed_client_with_control()
    content = b"specific evidence bytes to verify round-trip"
    client.post(
        f"/api/clients/{client_id}/compliance/{control_id}/evidence",
        headers=admin_user["headers"],
        files={"file": ("policy.txt", io.BytesIO(content), "text/plain")},
    )
    r = client.get(f"/api/clients/{client_id}/compliance/{control_id}/evidence", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.content == content


def test_download_evidence_404_when_none_uploaded(admin_user, client):
    client_id, control_id = _seed_client_with_control()
    r = client.get(f"/api/clients/{client_id}/compliance/{control_id}/evidence", headers=admin_user["headers"])
    assert r.status_code == 404


def test_evidence_upload_for_wrong_client_returns_404(admin_user, client):
    """IDOR check: a control belonging to client A shouldn't be uploadable-to via client B's URL."""
    client_id, control_id = _seed_client_with_control()
    db = SessionLocal()
    other_client = Client(id=str(uuid.uuid4()), name="Other Co", root_domain="other.example.com", contact_email="a@other.example.com")
    db.add(other_client)
    db.commit()
    other_id = other_client.id
    db.close()

    fake_file = io.BytesIO(b"content")
    r = client.post(
        f"/api/clients/{other_id}/compliance/{control_id}/evidence",
        headers=admin_user["headers"],
        files={"file": ("policy.pdf", fake_file, "application/pdf")},
    )
    assert r.status_code == 404


def test_export_compliance_report_returns_real_pdf(admin_user, client):
    client_id, control_id = _seed_client_with_control()
    r = client.get(f"/api/clients/{client_id}/compliance/export/pdf", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_list_controls_reflects_has_evidence_without_leaking_path(admin_user, client):
    client_id, control_id = _seed_client_with_control()

    r = client.get(f"/api/clients/{client_id}/compliance", headers=admin_user["headers"])
    control_before = next(c for c in r.json() if c["id"] == control_id)
    assert control_before["has_evidence"] is False
    assert "evidence_file_path" not in control_before

    client.post(
        f"/api/clients/{client_id}/compliance/{control_id}/evidence",
        headers=admin_user["headers"],
        files={"file": ("policy.pdf", io.BytesIO(b"content"), "application/pdf")},
    )

    r = client.get(f"/api/clients/{client_id}/compliance", headers=admin_user["headers"])
    control_after = next(c for c in r.json() if c["id"] == control_id)
    assert control_after["has_evidence"] is True
    assert "evidence_file_path" not in control_after
