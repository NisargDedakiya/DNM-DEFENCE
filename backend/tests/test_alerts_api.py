import uuid

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.models.models import Client, User, UserRole


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Alerts API Co", root_domain="alerts-api.example.com",
               contact_email="a@alerts-api.example.com")
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


def test_list_alert_log_empty(admin_user, client):
    client_id = _seed_client()
    r = client.get(f"/api/clients/{client_id}/alerts", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json() == []


def test_send_alert_persists_to_log_and_is_listable(admin_user, client):
    client_id = _seed_client()
    from app.core.database import SessionLocal as SL
    from app.models.models import Finding, Severity, FindingStatus
    db = SL()
    finding = Finding(client_id=client_id, title="Exposed S3 bucket", severity=Severity.critical, status=FindingStatus.new,
                      dedup_hash=uuid.uuid4().hex)
    db.add(finding)
    db.commit()
    finding_id = finding.id
    db.close()

    from unittest.mock import patch
    with patch("app.api.findings.ai_reports.draft_alert_notification", return_value="Draft body."), \
         patch("app.api.findings.notifications.notify_finding_alert", return_value={"email": True, "slack": False}):
        r = client.post(f"/api/clients/{client_id}/findings/{finding_id}/send-alert", headers=admin_user["headers"])
    assert r.status_code == 200

    r = client.get(f"/api/clients/{client_id}/alerts", headers=admin_user["headers"])
    assert r.status_code == 200
    entries = r.json()
    assert len(entries) == 1
    assert entries[0]["alert_type"] == "finding_alert"
    assert entries[0]["channel_email_sent"] is True
    assert entries[0]["channel_slack_sent"] is False
    assert entries[0]["finding_id"] == finding_id


def test_export_alert_log_csv(admin_user, client):
    client_id = _seed_client()
    from app.core.database import SessionLocal as SL
    from app.services.notifications import log_alert
    db = SL()
    log_alert(db, client_id, "weekly_threat_digest", "Weekly Threat Digest — Alerts API Co", {"email": True, "slack": True})
    db.close()

    r = client.get(f"/api/clients/{client_id}/alerts/export/csv", headers=admin_user["headers"])
    assert r.status_code == 200
    assert "weekly_threat_digest" in r.text
    assert "Weekly Threat Digest — Alerts API Co" in r.text


def test_client_role_can_view_own_alert_log(admin_user, client):
    """Unlike the Advanced Services routers, alert history is client-visible — clients should be able to see and download their own send history."""
    client_id = _seed_client()
    headers = _client_role_headers(client_id)
    r = client.get(f"/api/clients/{client_id}/alerts", headers=headers)
    assert r.status_code == 200

    r = client.get(f"/api/clients/{client_id}/alerts/export/csv", headers=headers)
    assert r.status_code == 200


def test_client_role_cannot_view_another_clients_alert_log(admin_user, client):
    client_a = _seed_client()
    client_b = _seed_client()
    headers_for_a = _client_role_headers(client_a)
    r = client.get(f"/api/clients/{client_b}/alerts", headers=headers_for_a)
    assert r.status_code == 403


def test_alerts_list_not_found_for_unknown_client(admin_user, client):
    r = client.get(f"/api/clients/{uuid.uuid4()}/alerts", headers=admin_user["headers"])
    assert r.status_code == 404
