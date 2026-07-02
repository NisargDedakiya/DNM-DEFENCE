import uuid

from app.core.database import SessionLocal
from app.core.auth import hash_password
from app.models.models import Client, User, UserRole, PhishingCampaign, PhishingResult, PhishingCampaignStatus


def _seed_campaign_with_results(show_names=False):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Phish Co", root_domain="phish.example.com",
               contact_email="a@phish.example.com", phishing_show_employee_names=show_names)
    db.add(c)
    db.commit()

    campaign = PhishingCampaign(id=str(uuid.uuid4()), client_id=c.id, name="Q1 Test", status=PhishingCampaignStatus.completed)
    db.add(campaign)
    db.commit()

    db.add(PhishingResult(id=str(uuid.uuid4()), campaign_id=campaign.id, employee_identifier="jane.doe@phish.example.com",
                           clicked=True, training_completed=True))
    db.add(PhishingResult(id=str(uuid.uuid4()), campaign_id=campaign.id, employee_identifier="john.smith@phish.example.com",
                           clicked=False, training_completed=False))
    db.commit()

    ids = (c.id, campaign.id)
    db.close()
    return ids


def _make_client_user(client_id):
    db = SessionLocal()
    email, password = f"portal-{uuid.uuid4().hex[:8]}@phish.example.com", "TestPassword123!"
    db.add(User(id=str(uuid.uuid4()), email=email, hashed_password=hash_password(password),
                role=UserRole.client, client_id=client_id))
    db.commit()
    db.close()
    return email, password


def test_client_role_sees_anonymized_names_by_default(client):
    client_id, campaign_id = _seed_campaign_with_results(show_names=False)
    email, password = _make_client_user(client_id)
    token = client.post("/api/auth/login", data={"username": email, "password": password}).json()["access_token"]

    r = client.get(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/results",
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    identifiers = [res["employee_identifier"] for res in r.json()]
    assert all(i.startswith("Employee #") for i in identifiers)
    assert "jane.doe@phish.example.com" not in identifiers


def test_client_role_sees_real_names_when_client_opted_in(client):
    client_id, campaign_id = _seed_campaign_with_results(show_names=True)
    email, password = _make_client_user(client_id)
    token = client.post("/api/auth/login", data={"username": email, "password": password}).json()["access_token"]

    r = client.get(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/results",
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    identifiers = [res["employee_identifier"] for res in r.json()]
    assert "jane.doe@phish.example.com" in identifiers


def test_staff_always_sees_real_names_regardless_of_client_setting(admin_user, client):
    client_id, campaign_id = _seed_campaign_with_results(show_names=False)  # client has NOT opted in
    r = client.get(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/results", headers=admin_user["headers"])
    assert r.status_code == 200
    identifiers = [res["employee_identifier"] for res in r.json()]
    assert "jane.doe@phish.example.com" in identifiers


def test_training_completion_rollup(admin_user, client):
    client_id, campaign_id = _seed_campaign_with_results()
    r = client.get(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/training-completion", headers=admin_user["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["total_employees"] == 2
    assert body["completed"] == 1
    assert body["percent_completed"] == 50
