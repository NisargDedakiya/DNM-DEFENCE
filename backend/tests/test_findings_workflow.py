import uuid

from app.core.database import SessionLocal
from app.models.models import Client, Finding, Severity, FindingStatus, MetricSnapshot


def _seed_client_and_finding(status=FindingStatus.new):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Workflow Co", root_domain="workflow.example.com", contact_email="a@workflow.example.com")
    db.add(c)
    db.commit()
    finding = Finding(id=str(uuid.uuid4()), client_id=c.id, title="Test finding",
                       severity=Severity.high, status=status, dedup_hash=str(uuid.uuid4()))
    db.add(finding)
    db.commit()
    ids = (c.id, finding.id)
    db.close()
    return ids


def test_status_transition_new_to_resolved_directly_is_rejected(admin_user, client):
    client_id, finding_id = _seed_client_and_finding(status=FindingStatus.new)
    r = client.patch(f"/api/clients/{client_id}/findings/{finding_id}", headers=admin_user["headers"],
                      json={"status": "resolved"})
    assert r.status_code == 400
    assert "acknowledged" in r.json()["detail"]  # tells the caller what IS allowed


def test_status_transition_new_to_acknowledged_succeeds(admin_user, client):
    client_id, finding_id = _seed_client_and_finding(status=FindingStatus.new)
    r = client.patch(f"/api/clients/{client_id}/findings/{finding_id}", headers=admin_user["headers"],
                      json={"status": "acknowledged"})
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"


def test_status_transition_full_lifecycle_in_order_succeeds(admin_user, client):
    client_id, finding_id = _seed_client_and_finding(status=FindingStatus.new)
    for next_status in ("acknowledged", "in_remediation", "resolved", "verified"):
        r = client.patch(f"/api/clients/{client_id}/findings/{finding_id}", headers=admin_user["headers"],
                          json={"status": next_status})
        assert r.status_code == 200, f"transition to {next_status} failed: {r.json()}"
        assert r.json()["status"] == next_status


def test_status_transition_to_disputed_allowed_from_any_state(admin_user, client):
    client_id, finding_id = _seed_client_and_finding(status=FindingStatus.in_remediation)
    r = client.patch(f"/api/clients/{client_id}/findings/{finding_id}", headers=admin_user["headers"],
                      json={"status": "disputed"})
    assert r.status_code == 200


def test_status_transition_same_status_is_a_noop_not_an_error(admin_user, client):
    client_id, finding_id = _seed_client_and_finding(status=FindingStatus.acknowledged)
    r = client.patch(f"/api/clients/{client_id}/findings/{finding_id}", headers=admin_user["headers"],
                      json={"status": "acknowledged"})
    assert r.status_code == 200


def test_assign_finding_to_valid_user(admin_user, client):
    client_id, finding_id = _seed_client_and_finding()
    r = client.patch(f"/api/clients/{client_id}/findings/{finding_id}/assign", headers=admin_user["headers"],
                      json={"assigned_to": _admin_user_id(admin_user)})
    assert r.status_code == 200
    assert r.json()["assigned_to"] is not None


def test_assign_finding_to_nonexistent_user_returns_404(admin_user, client):
    client_id, finding_id = _seed_client_and_finding()
    r = client.patch(f"/api/clients/{client_id}/findings/{finding_id}/assign", headers=admin_user["headers"],
                      json={"assigned_to": str(uuid.uuid4())})
    assert r.status_code == 404


def test_assign_finding_unassign_with_null(admin_user, client):
    client_id, finding_id = _seed_client_and_finding()
    client.patch(f"/api/clients/{client_id}/findings/{finding_id}/assign", headers=admin_user["headers"],
                 json={"assigned_to": _admin_user_id(admin_user)})
    r = client.patch(f"/api/clients/{client_id}/findings/{finding_id}/assign", headers=admin_user["headers"],
                      json={"assigned_to": None})
    assert r.status_code == 200
    assert r.json()["assigned_to"] is None


def test_findings_trend_endpoint_returns_snapshots_in_range(admin_user, client):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Trend Co", root_domain="trend.example.com", contact_email="a@trend.example.com")
    db.add(c)
    db.commit()
    from datetime import datetime, timedelta
    db.add(MetricSnapshot(id=str(uuid.uuid4()), client_id=c.id, snapshot_date=datetime.utcnow() - timedelta(days=5),
                           critical_count=1, high_count=2, medium_count=0, low_count=0, risk_score=45))
    db.add(MetricSnapshot(id=str(uuid.uuid4()), client_id=c.id, snapshot_date=datetime.utcnow() - timedelta(days=400),
                           critical_count=9, high_count=9, medium_count=0, low_count=0, risk_score=99))
    db.commit()
    client_id = c.id
    db.close()

    r = client.get(f"/api/clients/{client_id}/findings/trend?months=3", headers=admin_user["headers"])
    assert r.status_code == 200
    points = r.json()
    assert len(points) == 1  # only the in-range snapshot
    assert points[0]["risk_score"] == 45


def _admin_user_id(admin_user):
    db = SessionLocal()
    from app.models.models import User
    user = db.query(User).filter_by(email=admin_user["email"]).first()
    uid = user.id
    db.close()
    return uid
