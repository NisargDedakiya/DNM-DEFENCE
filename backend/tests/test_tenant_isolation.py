"""
Tenant isolation tests -- the audit flagged this as needing coverage.
This is the mechanism that actually prevents one client's portal user
from reading another client's data, so it gets its own dedicated test.
"""
import uuid


def test_client_role_cannot_list_all_clients(client, admin_user):
    """The full client roster is staff-only -- a client user has no reason to see other clients."""
    from app.core.database import SessionLocal
    from app.core.auth import hash_password, create_access_token
    from app.models.models import User, UserRole, Client

    db = SessionLocal()
    target = Client(id=str(uuid.uuid4()), name="Acme", root_domain="acme.example.com", contact_email="a@acme.example.com")
    db.add(target)
    db.commit()

    client_user = User(id=str(uuid.uuid4()), email="client@acme.example.com",
                        hashed_password=hash_password("pw"), role=UserRole.client, client_id=target.id)
    db.add(client_user)
    db.commit()
    token = create_access_token(client_user)
    db.close()

    r = client.get("/api/clients", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_client_role_cannot_access_another_clients_assets(client):
    """The core isolation guarantee: a client-role token for client A cannot read client B's assets via require_client_access."""
    from app.core.database import SessionLocal
    from app.core.auth import hash_password, create_access_token
    from app.models.models import User, UserRole, Client

    db = SessionLocal()
    client_a = Client(id=str(uuid.uuid4()), name="Client A", root_domain="a.example.com", contact_email="a@a.example.com")
    client_b = Client(id=str(uuid.uuid4()), name="Client B", root_domain="b.example.com", contact_email="a@b.example.com")
    db.add_all([client_a, client_b])
    db.commit()

    user_a = User(id=str(uuid.uuid4()), email="user@a.example.com",
                  hashed_password=hash_password("pw"), role=UserRole.client, client_id=client_a.id)
    db.add(user_a)
    db.commit()
    token_a = create_access_token(user_a)
    client_b_id = client_b.id
    db.close()

    # user_a's token trying to read client_b's assets -- must be rejected
    r = client.get(f"/api/clients/{client_b_id}/assets", headers={"Authorization": f"Bearer {token_a}"})
    assert r.status_code == 403


def test_client_role_can_access_own_clients_assets(client):
    """Sanity check: the same user CAN access their own client's data."""
    from app.core.database import SessionLocal
    from app.core.auth import hash_password, create_access_token
    from app.models.models import User, UserRole, Client

    db = SessionLocal()
    own_client = Client(id=str(uuid.uuid4()), name="Own Co", root_domain="own.example.com", contact_email="a@own.example.com")
    db.add(own_client)
    db.commit()

    user = User(id=str(uuid.uuid4()), email="user@own.example.com",
                hashed_password=hash_password("pw"), role=UserRole.client, client_id=own_client.id)
    db.add(user)
    db.commit()
    token = create_access_token(user)
    own_client_id = own_client.id
    db.close()

    r = client.get(f"/api/clients/{own_client_id}/assets", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_staff_can_access_any_clients_data(client, admin_user):
    """Sanity check: staff (admin/analyst) roles bypass the per-client restriction by design."""
    from app.core.database import SessionLocal
    from app.models.models import Client

    db = SessionLocal()
    some_client = Client(id=str(uuid.uuid4()), name="Any Co", root_domain="any.example.com", contact_email="a@any.example.com")
    db.add(some_client)
    db.commit()
    some_client_id = some_client.id
    db.close()

    r = client.get(f"/api/clients/{some_client_id}/assets", headers=admin_user["headers"])
    assert r.status_code == 200
