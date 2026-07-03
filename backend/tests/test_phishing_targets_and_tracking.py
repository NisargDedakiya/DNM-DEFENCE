import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.models.models import Client, PhishingCampaign, PhishingTarget


def _seed_campaign():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Target Co", root_domain="target.example.com", contact_email="a@target.example.com")
    db.add(c)
    db.commit()
    campaign = PhishingCampaign(id=str(uuid.uuid4()), client_id=c.id, name="Q1 test")
    db.add(campaign)
    db.commit()
    ids = (c.id, campaign.id)
    db.close()
    return ids


def test_import_targets_creates_rows_and_bumps_target_count(admin_user, client):
    client_id, campaign_id = _seed_campaign()
    rows = [{"name": "Jane Doe", "role": "Engineer", "email": "jane@target.example.com"},
            {"name": "John Smith", "role": "Sales", "email": "john@target.example.com"}]
    r = client.post(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/targets/import",
                     headers=admin_user["headers"], json=rows)
    assert r.status_code == 201
    body = r.json()
    assert len(body) == 2
    assert "tracking_token" not in body[0]  # internal-only field, never exposed to the client

    db = SessionLocal()
    campaign = db.query(PhishingCampaign).get(campaign_id)
    assert campaign.target_count == 2
    db.close()


def test_set_template_and_send_campaign_uses_email_channel(admin_user, client):
    client_id, campaign_id = _seed_campaign()
    client.post(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/targets/import",
                headers=admin_user["headers"],
                json=[{"name": "Jane Doe", "role": "Engineer", "email": "jane@target.example.com"}])

    r = client.patch(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/template",
                      headers=admin_user["headers"],
                      json={"template_html": "Hi {target_name} ({target_role}) - <img src='{tracking_pixel}'><a href='{tracking_link}'>click</a>",
                            "campaign_type": "phishing"})
    assert r.status_code == 200

    with patch("app.api.phishing.send_email", return_value=True) as mock_send:
        r = client.post(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/send", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["sent"] == 1
    mock_send.assert_called_once()
    body_arg = mock_send.call_args.args[2]
    assert "Jane Doe" in body_arg
    assert "Engineer" in body_arg


def test_send_campaign_requires_template(admin_user, client):
    client_id, campaign_id = _seed_campaign()
    client.post(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/targets/import",
                headers=admin_user["headers"], json=[{"email": "jane@target.example.com"}])
    r = client.post(f"/api/clients/{client_id}/phishing-campaigns/{campaign_id}/send", headers=admin_user["headers"])
    assert r.status_code == 422


def test_tracking_pixel_marks_target_opened(client):
    client_id, campaign_id = _seed_campaign()
    db = SessionLocal()
    target = PhishingTarget(id=str(uuid.uuid4()), campaign_id=campaign_id, email="jane@target.example.com",
                             tracking_token="tok123")
    db.add(target)
    db.commit()
    db.close()

    r = client.get("/api/phishing-track/tok123/pixel.gif")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/gif"

    db = SessionLocal()
    updated = db.query(PhishingTarget).filter_by(tracking_token="tok123").first()
    assert updated.opened is True
    campaign = db.query(PhishingCampaign).get(campaign_id)
    assert campaign.opened_count == 1
    db.close()


def test_tracking_pixel_unknown_token_still_returns_gif(client):
    r = client.get("/api/phishing-track/does-not-exist/pixel.gif")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/gif"


def test_landing_page_marks_clicked_and_submit_never_stores_password(client):
    client_id, campaign_id = _seed_campaign()
    db = SessionLocal()
    target = PhishingTarget(id=str(uuid.uuid4()), campaign_id=campaign_id, email="jane@target.example.com",
                             tracking_token="tok456")
    db.add(target)
    db.commit()
    db.close()

    r = client.get("/api/phishing-track/tok456/landing")
    assert r.status_code == 200
    assert "Sign in" in r.text

    r = client.post("/api/phishing-track/tok456/submit", data={"email": "jane@x.com", "password": "hunter2"})
    assert r.status_code == 200
    assert "simulated phishing test" in r.text

    db = SessionLocal()
    updated = db.query(PhishingTarget).filter_by(tracking_token="tok456").first()
    assert updated.clicked is True
    assert updated.submitted_credentials is True
    campaign = db.query(PhishingCampaign).get(campaign_id)
    assert campaign.clicked_count == 1
    assert campaign.credential_submitted_count == 1
    db.close()
