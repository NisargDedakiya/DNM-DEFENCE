import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.models.models import User, UserRole


def _client_role_headers():
    db = SessionLocal()
    user = User(id=str(uuid.uuid4()), email=f"client-{uuid.uuid4().hex[:8]}@test.local",
                hashed_password=hash_password("pw"), role=UserRole.client)
    db.add(user)
    db.commit()
    token = create_access_token(user)
    db.close()
    return {"Authorization": f"Bearer {token}"}


def test_diagnostics_requires_staff(admin_user, client):
    r = client.get("/api/system/diagnostics", headers=_client_role_headers())
    assert r.status_code == 403


def test_diagnostics_returns_full_shape_for_staff(admin_user, client):
    with patch("app.services.system_diagnostics.check_redis", return_value=True), \
         patch("app.services.system_diagnostics.check_celery_workers", return_value={"reachable": True, "worker_count": 1}):
        r = client.get("/api/system/diagnostics", headers=admin_user["headers"])
    assert r.status_code == 200
    body = r.json()
    assert "healthy" in body
    assert "database" in body
    assert "redis" in body
    assert "celery" in body
    assert "required_recon_tools" in body
    assert "optional_tools" in body
    assert "ai_reports_configured" in body
    assert "warnings" in body


def test_operator_overview_requires_staff(admin_user, client):
    r = client.get("/api/system/operator-overview", headers=_client_role_headers())
    assert r.status_code == 403


def test_operator_overview_aggregates_across_clients(admin_user, client):
    import uuid
    from app.core.database import SessionLocal
    from app.models.models import Client, Finding, Severity, FindingStatus

    db = SessionLocal()
    c1 = Client(id=str(uuid.uuid4()), name="Alpha Co", root_domain="alpha.example.com", contact_email="a@alpha.example.com")
    c2 = Client(id=str(uuid.uuid4()), name="Beta Co", root_domain="beta.example.com", contact_email="b@beta.example.com")
    db.add_all([c1, c2])
    db.commit()
    # Alpha has a critical + a high open; Beta has a low.
    db.add_all([
        Finding(client_id=c1.id, title="crit", severity=Severity.critical, status=FindingStatus.new, dedup_hash=uuid.uuid4().hex),
        Finding(client_id=c1.id, title="high", severity=Severity.high, status=FindingStatus.new, dedup_hash=uuid.uuid4().hex),
        Finding(client_id=c2.id, title="low", severity=Severity.low, status=FindingStatus.new, dedup_hash=uuid.uuid4().hex),
        # A resolved finding must NOT count toward "open".
        Finding(client_id=c2.id, title="done", severity=Severity.critical, status=FindingStatus.resolved, dedup_hash=uuid.uuid4().hex),
    ])
    db.commit()
    db.close()

    with patch("app.services.system_diagnostics.check_redis", return_value=True), \
         patch("app.services.system_diagnostics.check_celery_workers", return_value={"reachable": True, "worker_count": 1}):
        r = client.get("/api/system/operator-overview", headers=admin_user["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["open_findings"]["by_severity"]["critical"] == 1  # resolved one excluded
    assert body["open_findings"]["by_severity"]["high"] == 1
    assert body["open_findings"]["by_severity"]["low"] == 1
    assert body["open_findings"]["total"] == 3
    # Leaderboard: Alpha (25+10=35) must rank above Beta (1).
    names = [c["client_name"] for c in body["risk_leaderboard"]]
    assert names.index("Alpha Co") < names.index("Beta Co")
