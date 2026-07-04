import uuid

from app.core.database import SessionLocal
from app.models.models import Client, User, UserRole


def _seed_client():
    """Seeds a Client directly via the DB session (bypassing POST /api/clients, which
    also queues a Celery scan job that needs a live broker not available in tests)."""
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Portal Access Co", root_domain=f"portal-access-{uuid.uuid4().hex[:8]}.example.com",
               contact_email="a@portal-access.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def test_create_client_user_provisions_scoped_login(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/users", headers=admin_user["headers"],
                     json={"email": "portaluser@portal-access.example.com", "password": "ClientPass123!"})
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "portaluser@portal-access.example.com"
    assert body["is_active"] is True

    db = SessionLocal()
    user = db.query(User).filter_by(email="portaluser@portal-access.example.com").first()
    assert user.role == UserRole.client
    assert user.client_id == client_id
    db.close()


def test_created_client_user_can_log_in_and_is_scoped_to_their_client(admin_user, client):
    client_id = _seed_client()
    client.post(f"/api/clients/{client_id}/users", headers=admin_user["headers"],
                json={"email": "loginuser@portal-access.example.com", "password": "ClientPass123!"})

    login = client.post("/api/auth/login", data={"username": "loginuser@portal-access.example.com", "password": "ClientPass123!"})
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    r = client.get(f"/api/clients/{client_id}", headers=headers)
    assert r.status_code == 200

    other_client_id = _seed_client()
    r = client.get(f"/api/clients/{other_client_id}", headers=headers)
    assert r.status_code == 403


def test_create_client_user_rejects_duplicate_email(admin_user, client):
    client_id = _seed_client()
    payload = {"email": "dup@portal-access.example.com", "password": "ClientPass123!"}
    client.post(f"/api/clients/{client_id}/users", headers=admin_user["headers"], json=payload)
    r = client.post(f"/api/clients/{client_id}/users", headers=admin_user["headers"], json=payload)
    assert r.status_code == 400


def test_create_client_user_404_for_unknown_client(admin_user, client):
    r = client.post(f"/api/clients/{uuid.uuid4()}/users", headers=admin_user["headers"],
                     json={"email": "nobody@example.com", "password": "ClientPass123!"})
    assert r.status_code == 404


def test_list_client_users_only_returns_that_clients_users(admin_user, client):
    client_a = _seed_client()
    client_b = _seed_client()
    client.post(f"/api/clients/{client_a}/users", headers=admin_user["headers"],
                json={"email": "a@portal-access.example.com", "password": "ClientPass123!"})
    client.post(f"/api/clients/{client_b}/users", headers=admin_user["headers"],
                json={"email": "b@portal-access.example.com", "password": "ClientPass123!"})

    r = client.get(f"/api/clients/{client_a}/users", headers=admin_user["headers"])
    assert r.status_code == 200
    emails = {u["email"] for u in r.json()}
    assert emails == {"a@portal-access.example.com"}


def test_revoke_and_restore_client_user_access(admin_user, client):
    client_id = _seed_client()
    created = client.post(f"/api/clients/{client_id}/users", headers=admin_user["headers"],
                           json={"email": "revoke-me@portal-access.example.com", "password": "ClientPass123!"}).json()

    r = client.patch(f"/api/clients/{client_id}/users/{created['id']}", headers=admin_user["headers"], json={"is_active": False})
    assert r.status_code == 200
    assert r.json()["is_active"] is False

    login = client.post("/api/auth/login", data={"username": "revoke-me@portal-access.example.com", "password": "ClientPass123!"})
    assert login.status_code == 401

    r = client.patch(f"/api/clients/{client_id}/users/{created['id']}", headers=admin_user["headers"], json={"is_active": True})
    assert r.status_code == 200
    login2 = client.post("/api/auth/login", data={"username": "revoke-me@portal-access.example.com", "password": "ClientPass123!"})
    assert login2.status_code == 200


def test_update_client_user_404_for_user_from_different_client(admin_user, client):
    client_a = _seed_client()
    client_b = _seed_client()
    created = client.post(f"/api/clients/{client_a}/users", headers=admin_user["headers"],
                           json={"email": "cross-client@portal-access.example.com", "password": "ClientPass123!"}).json()

    r = client.patch(f"/api/clients/{client_b}/users/{created['id']}", headers=admin_user["headers"], json={"is_active": False})
    assert r.status_code == 404


def test_client_role_user_cannot_manage_portal_users(admin_user, client):
    client_id = _seed_client()
    client.post(f"/api/clients/{client_id}/users", headers=admin_user["headers"],
                json={"email": "notstaff@portal-access.example.com", "password": "ClientPass123!"})
    login = client.post("/api/auth/login", data={"username": "notstaff@portal-access.example.com", "password": "ClientPass123!"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    r = client.get(f"/api/clients/{client_id}/users", headers=headers)
    assert r.status_code == 403
    r = client.post(f"/api/clients/{client_id}/users", headers=headers, json={"email": "x@example.com", "password": "ClientPass123!"})
    assert r.status_code == 403
