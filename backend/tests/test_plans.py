import uuid

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.core.plans import PlanTier, plan_has_feature, plan_allows_scan, public_plans
from app.models.models import Client, User, UserRole


def _seed_client(plan="enterprise"):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Plan Co", root_domain="plan.example.com",
               contact_email="a@plan.example.com", plan=plan)
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def _client_headers(client_id):
    db = SessionLocal()
    u = User(id=str(uuid.uuid4()), email=f"c-{uuid.uuid4().hex[:8]}@t.local",
             hashed_password=hash_password("pw"), role=UserRole.client, client_id=client_id)
    db.add(u)
    db.commit()
    tok = create_access_token(u)
    db.close()
    return {"Authorization": f"Bearer {tok}"}


# --- plan config ---

def test_tiers_are_nested_supersets():
    ess = {"asset_discovery", "vulnerability_management", "security_scorecard", "reports", "compliance", "alerts"}
    for f in ess:
        assert plan_has_feature(PlanTier.essential, f)
    # growth adds cloud + threat intel + phishing but keeps everything essential has
    assert plan_has_feature(PlanTier.growth, "cloud_security")
    assert not plan_has_feature(PlanTier.essential, "cloud_security")
    # enterprise is the widest
    assert plan_has_feature(PlanTier.enterprise, "mobile_security")
    assert not plan_has_feature(PlanTier.growth, "mobile_security")


def test_plan_allows_scan_gates_by_tier():
    assert plan_allows_scan(PlanTier.essential, "dark_web_scan") is False
    assert plan_allows_scan(PlanTier.growth, "dark_web_scan") is True
    assert plan_allows_scan(PlanTier.essential, "cloud_audit") is False
    assert plan_allows_scan(PlanTier.enterprise, "cloud_audit") is True
    # scans not tied to any gated feature are available on every tier
    assert plan_allows_scan(PlanTier.essential, "subdomain_enum") is True


def test_public_plans_catalogue_shape():
    plans = public_plans()
    assert [p["tier"] for p in plans] == ["essential", "growth", "enterprise"]
    assert plans[0]["price_monthly_usd"] < plans[2]["price_monthly_usd"]
    for p in plans:
        assert any(f["included"] for f in p["features"])


# --- catalogue + subscription API ---

def test_plans_catalogue_endpoint(admin_user, client):
    r = client.get("/api/plans", headers=admin_user["headers"])
    assert r.status_code == 200
    assert len(r.json()) == 3


def test_get_subscription_reports_entitlements(admin_user, client):
    cid = _seed_client(plan="growth")
    r = client.get(f"/api/clients/{cid}/subscription", headers=admin_user["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["plan"] == "growth"
    assert body["entitlements"]["cloud_security"] is True
    assert body["entitlements"]["mobile_security"] is False


def test_set_subscription_applies_plan_slas(admin_user, client):
    cid = _seed_client(plan="essential")
    r = client.put(f"/api/clients/{cid}/subscription", headers=admin_user["headers"], json={"plan": "enterprise"})
    assert r.status_code == 200
    assert r.json()["plan"] == "enterprise"
    db = SessionLocal()
    c = db.query(Client).get(cid)
    assert c.plan == "enterprise"
    assert c.sla_hours_critical == 8  # enterprise SLA applied
    db.close()


def test_set_subscription_rejects_invalid_plan(admin_user, client):
    cid = _seed_client()
    r = client.put(f"/api/clients/{cid}/subscription", headers=admin_user["headers"], json={"plan": "free"})
    assert r.status_code == 422


def test_client_role_cannot_change_own_plan(admin_user, client):
    cid = _seed_client(plan="essential")
    headers = _client_headers(cid)
    r = client.put(f"/api/clients/{cid}/subscription", headers=headers, json={"plan": "enterprise"})
    assert r.status_code == 403


# --- entitlement gating on feature routers ---

def test_essential_client_blocked_from_cloud_security(admin_user, client):
    cid = _seed_client(plan="essential")
    headers = _client_headers(cid)
    r = client.get(f"/api/clients/{cid}/cloud-accounts", headers=headers)
    assert r.status_code == 402
    assert "Upgrade" in r.json()["detail"]


def test_growth_client_allowed_cloud_but_blocked_from_mobile(admin_user, client):
    cid = _seed_client(plan="growth")
    headers = _client_headers(cid)
    assert client.get(f"/api/clients/{cid}/cloud-accounts", headers=headers).status_code == 200
    assert client.get(f"/api/clients/{cid}/mobile-scans", headers=headers).status_code == 402


def test_enterprise_client_allowed_everything(admin_user, client):
    cid = _seed_client(plan="enterprise")
    headers = _client_headers(cid)
    for path in ("cloud-accounts", "mobile-scans", "web3/contract-audits", "ai-security/feature-inventory"):
        r = client.get(f"/api/clients/{cid}/{path}", headers=headers)
        assert r.status_code == 200, f"{path} -> {r.status_code}"


def test_staff_never_plan_gated(admin_user, client):
    """An essential client's data is still fully reachable by staff, who deliver the service."""
    cid = _seed_client(plan="essential")
    r = client.get(f"/api/clients/{cid}/mobile-scans", headers=admin_user["headers"])
    assert r.status_code == 200


def test_onboarding_accepts_plan(admin_user, client):
    from unittest.mock import patch
    with patch("app.api.clients.run_subdomain_enum_for_client.delay"):
        r = client.post("/api/clients", headers=admin_user["headers"], json={
            "name": "Tiered Co", "root_domain": "tiered.example.com",
            "contact_email": "a@tiered.example.com", "plan": "growth",
        })
    assert r.status_code == 201
    assert r.json()["plan"] == "growth"
