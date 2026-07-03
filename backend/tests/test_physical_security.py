import uuid

from app.core.database import SessionLocal
from app.models.models import Client


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Physec Co", root_domain="physec.example.com", contact_email="a@physec.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def test_create_assessment_seeds_all_checklist_test_types(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/physical-security", headers=admin_user["headers"],
                     json={"site_name": "HQ - Bengaluru"})
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "scheduled"
    test_types = {item["test_type"] for item in body["checklist_items"]}
    assert test_types == {"tailgating", "badge_cloning", "dumpster_diving", "visitor_access", "clean_desk", "usb_drop"}
    assert all(item["attempted"] is False for item in body["checklist_items"])


def test_update_checklist_item_records_outcome(admin_user, client):
    client_id = _seed_client()
    created = client.post(f"/api/clients/{client_id}/physical-security", headers=admin_user["headers"],
                           json={"site_name": "HQ"}).json()
    item = created["checklist_items"][0]

    r = client.patch(
        f"/api/clients/{client_id}/physical-security/{created['id']}/checklist/{item['id']}",
        headers=admin_user["headers"],
        json={"attempted": True, "outcome_notes": "Tailgated through the east entrance without a badge check.", "severity": "high"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["attempted"] is True
    assert "Tailgated" in body["outcome_notes"]
    assert body["severity"] == "high"


def test_update_assessment_status_and_summary(admin_user, client):
    client_id = _seed_client()
    created = client.post(f"/api/clients/{client_id}/physical-security", headers=admin_user["headers"],
                           json={"site_name": "HQ"}).json()
    r = client.patch(f"/api/clients/{client_id}/physical-security/{created['id']}", headers=admin_user["headers"],
                      json={"status": "completed", "summary": "All tests attempted; 2 findings raised."})
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
    assert "2 findings" in r.json()["summary"]


def test_checklist_item_for_wrong_assessment_returns_404(admin_user, client):
    """IDOR check: an item belonging to assessment A shouldn't be updatable via assessment B's URL."""
    client_id = _seed_client()
    a1 = client.post(f"/api/clients/{client_id}/physical-security", headers=admin_user["headers"], json={"site_name": "Site 1"}).json()
    a2 = client.post(f"/api/clients/{client_id}/physical-security", headers=admin_user["headers"], json={"site_name": "Site 2"}).json()
    item_from_a1 = a1["checklist_items"][0]

    r = client.patch(
        f"/api/clients/{client_id}/physical-security/{a2['id']}/checklist/{item_from_a1['id']}",
        headers=admin_user["headers"], json={"attempted": True},
    )
    assert r.status_code == 404
