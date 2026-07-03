import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.models.models import Client


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="AI API Co", root_domain="ai-api.example.com", contact_email="a@ai-api.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def test_create_prompt_injection_test_syncs_findings(admin_user, client):
    client_id = _seed_client()
    fake_classified = [
        {"payload": {"category": "direct_injection", "payload": "ignore everything"}, "response_text": "leaked", "classification": {"success": True, "confidence": "high", "reason": "leaked"}},
        {"payload": {"category": "jailbreak", "payload": "roleplay"}, "response_text": "refused", "classification": {"success": False, "confidence": "low", "reason": "refused"}},
    ]
    with patch("app.api.ai_security.run_and_classify", return_value=fake_classified):
        r = client.post(f"/api/clients/{client_id}/ai-security/prompt-injection-tests", headers=admin_user["headers"],
                         json={"target_url": "https://target.example.com/chat"})
    assert r.status_code == 201
    body = r.json()
    assert body["success_count"] == 1
    assert len(body["results"]) == 2

    r = client.get(f"/api/clients/{client_id}/findings", headers=admin_user["headers"])
    assert any("direct injection" in f["title"] for f in r.json())


def test_list_prompt_injection_tests(admin_user, client):
    client_id = _seed_client()
    with patch("app.api.ai_security.run_and_classify", return_value=[]):
        client.post(f"/api/clients/{client_id}/ai-security/prompt-injection-tests", headers=admin_user["headers"],
                    json={"target_url": "https://target.example.com/chat"})
    r = client.get(f"/api/clients/{client_id}/ai-security/prompt-injection-tests", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_feature_inventory_crud(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/ai-security/feature-inventory", headers=admin_user["headers"],
                     json={"feature_name": "Support chatbot", "feature_type": "chatbot", "library_stack": {"langchain": "0.1.0"}})
    assert r.status_code == 201

    r = client.get(f"/api/clients/{client_id}/ai-security/feature-inventory", headers=admin_user["headers"])
    assert len(r.json()) == 1
    assert r.json()[0]["library_stack"]["langchain"] == "0.1.0"


def test_cve_check_aggregates_across_features(admin_user, client):
    client_id = _seed_client()
    client.post(f"/api/clients/{client_id}/ai-security/feature-inventory", headers=admin_user["headers"],
                json={"feature_name": "Bot", "library_stack": {"langchain": "0.1.0"}})

    with patch("app.api.ai_security.check_ai_library_cves", return_value=[{"library": "langchain", "version": "0.1.0", "cve_id": "CVE-1", "summary": "s", "cvss": 7.0}]) as mock_check:
        r = client.get(f"/api/clients/{client_id}/ai-security/cve-check", headers=admin_user["headers"])
    assert r.status_code == 200
    assert len(r.json()["hits"]) == 1
    mock_check.assert_called_once_with({"langchain": "0.1.0"})


def test_posture_brief_uses_owasp_llm_compliance_summary(admin_user, client):
    client_id = _seed_client()
    with patch("app.api.ai_security.check_ai_library_cves", return_value=[]), \
         patch("app.api.ai_security.generate_ai_security_brief", return_value="All good.") as mock_brief:
        r = client.get(f"/api/clients/{client_id}/ai-security/posture-brief", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["brief"] == "All good."
    mock_brief.assert_called_once()


def test_owasp_llm_framework_seeded_on_client_creation(admin_user, client):
    # Celery/Redis aren't available in this test environment -- mock the
    # post-onboarding scan trigger so this test only exercises compliance
    # seeding, matching the pattern other client-creation tests use.
    with patch("app.api.clients.run_subdomain_enum_for_client.delay"):
        r = client.post("/api/clients", headers=admin_user["headers"], json={
            "name": "Seeded Co", "root_domain": "seeded.example.com", "contact_email": "a@seeded.example.com",
        })
    assert r.status_code == 201
    client_id = r.json()["id"]

    r = client.get(f"/api/clients/{client_id}/compliance", headers=admin_user["headers"], params={"framework": "owasp_llm"})
    assert r.status_code == 200
    controls = r.json()
    assert len(controls) == 10
    assert {c["control_id"] for c in controls} == {f"LLM{i:02d}" for i in range(1, 11)}
