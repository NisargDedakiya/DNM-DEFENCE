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
