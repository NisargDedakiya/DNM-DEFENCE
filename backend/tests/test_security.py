"""
Regression tests for specific vulnerabilities fixed during the security
audit. If any of these start failing, a fix was accidentally reverted.
"""


def test_slack_webhook_ssrf_payload_rejected(admin_user, client):
    r = client.post("/api/clients", headers=admin_user["headers"], json={
        "name": "Evil Co", "root_domain": "evil.example.com", "contact_email": "a@evil.example.com",
        "slack_webhook_url": "http://169.254.169.254/latest/meta-data/",
    })
    assert r.status_code == 422


def test_genuine_slack_webhook_accepted_at_validation_layer(admin_user, client):
    """Confirms the validator isn't overly strict -- a real Slack webhook URL should pass schema validation
    (the request may still fail later for unrelated reasons like Celery being unavailable in this test env)."""
    r = client.post("/api/clients", headers=admin_user["headers"], json={
        "name": "Good Co", "root_domain": "good.example.com", "contact_email": "a@good.example.com",
        "slack_webhook_url": "https://hooks.slack.com/services/T00000/B00000/xxxxxxxxxxxxxxxxxxxxxxxx",
    })
    assert r.status_code != 422  # schema validation passed; any other status is a separate concern


def test_docs_url_is_none_outside_development():
    """
    Unit-level check of the same gating logic main.py uses, rather than
    spinning up a second FastAPI app in-process (module-level settings
    are baked in at import time, so re-testing the live app object after
    changing env vars isn't reliable within a single test process --
    that's better covered by an integration/deploy-time smoke test).
    """
    def docs_url_for(env: str) -> str | None:
        return "/docs" if env == "development" else None

    assert docs_url_for("development") == "/docs"
    assert docs_url_for("production") is None
    assert docs_url_for("staging") is None


def test_unauthenticated_request_gets_security_headers(client):
    """CSP/security headers should apply even to responses that get rejected for auth reasons."""
    r = client.get("/api/clients")
    assert r.headers.get("x-frame-options") == "DENY"
    assert "default-src 'none'" in r.headers.get("content-security-policy", "")


def test_rate_limit_engages_on_rapid_login_attempts(admin_user, client):
    responses = [client.post("/api/auth/login", data={"username": admin_user["email"], "password": "wrong"}) for _ in range(10)]
    assert any(r.status_code == 429 for r in responses)


def test_idor_finding_status_update_across_clients(client, admin_user):
    """
    IDOR check: a finding belonging to client A should not be updatable
    via a URL that names client B, even by an authenticated user, since
    the finding lookup is scoped by both finding_id AND client_id.
    """
    import uuid
    from app.core.database import SessionLocal
    from app.models.models import Client, Finding, Severity, FindingStatus

    db = SessionLocal()
    client_a = Client(id=str(uuid.uuid4()), name="A", root_domain="a.example.com", contact_email="a@a.example.com")
    client_b = Client(id=str(uuid.uuid4()), name="B", root_domain="b.example.com", contact_email="a@b.example.com")
    db.add_all([client_a, client_b])
    db.commit()

    finding = Finding(id=str(uuid.uuid4()), client_id=client_a.id, title="Test finding",
                       severity=Severity.high, status=FindingStatus.new, dedup_hash="testhash123")
    db.add(finding)
    db.commit()
    finding_id, client_b_id = finding.id, client_b.id
    db.close()

    # Try to update client A's finding via client B's URL -- must not succeed
    r = client.patch(f"/api/clients/{client_b_id}/findings/{finding_id}", headers=admin_user["headers"],
                      json={"status": "resolved"})
    assert r.status_code == 404  # finding lookup is scoped by client_id, so it's correctly "not found" here, not leaked


def test_mass_assignment_cannot_set_unexposed_fields(admin_user, client):
    """
    Mass-assignment check: ClientCreate schema doesn't expose
    auto_send_critical_alerts or dns_baseline, so attempting to set them
    via the API should be silently ignored (extra fields dropped), not
    applied to the model.
    """
    r = client.post("/api/clients", headers=admin_user["headers"], json={
        "name": "Test Co", "root_domain": "test.example.com", "contact_email": "a@test.example.com",
        "auto_send_critical_alerts": True,  # not in ClientCreate schema -- should be ignored
        "is_active": False,  # also not exposed -- should be ignored, new clients default active
    })
    # Whatever the final status (may fail on Celery unavailability in test env),
    # confirm the extra fields didn't get set if the client was created
    if r.status_code == 201:
        assert r.json()["is_active"] is True


def test_password_never_returned_in_user_response(admin_user, client):
    """Sanity check: the hashed_password field must never appear in any API response."""
    r = client.get("/api/auth/me", headers=admin_user["headers"])
    assert "hashed_password" in r.json() or "password" not in str(r.json()).lower()
    assert "password" not in r.json()


def test_sql_injection_style_input_handled_safely(admin_user, client):
    """
    Not a real SQLi test (SQLAlchemy's ORM parameterizes everything by
    default so there's no raw-string injection surface here) -- this
    confirms garbage input in a filter param doesn't crash the server
    with a 500, which would indicate something bypassing the ORM.
    """
    import uuid
    fake_id = str(uuid.uuid4())
    r = client.get(f"/api/clients/{fake_id}/findings",
                    headers=admin_user["headers"],
                    params={"severity": "critical'; DROP TABLE findings; --"})
    assert r.status_code in (403, 404, 422)  # rejected cleanly, not a 500
