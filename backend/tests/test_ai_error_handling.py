"""
Every AI-backed endpoint calls Anthropic synchronously. A missing/invalid/
unreachable key must surface as a clean, actionable 503 -- never an opaque
500 -- so an operator who hasn't configured a real key understands *why*
"no report generated" and that only AI features are affected. These tests
lock in the global exception handlers that guarantee that.
"""
import uuid
from unittest.mock import patch

import anthropic

from app.core.database import SessionLocal
from app.models.models import Client


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="AI Err Co", root_domain="ai-err.example.com",
               contact_email="a@ai-err.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def test_invalid_key_returns_clean_503_not_500(admin_user, client):
    """Key present but invalid/revoked/rate-limited -> anthropic.AnthropicError -> 503."""
    client_id = _seed_client()
    with patch("app.api.ai_security.check_ai_library_cves", return_value=[]), \
         patch("app.api.ai_security.generate_ai_security_brief",
               side_effect=anthropic.AnthropicError("invalid x-api-key")):
        r = client.get(f"/api/clients/{client_id}/ai-security/posture-brief", headers=admin_user["headers"])
    assert r.status_code == 503
    assert "ANTHROPIC_API_KEY" in r.json()["detail"]


def test_unset_key_runtime_error_returns_clean_503(admin_user, client):
    """Key unset -> _claude_client() raises RuntimeError -> 503 (same clean message)."""
    client_id = _seed_client()
    with patch("app.api.ai_security.check_ai_library_cves", return_value=[]), \
         patch("app.api.ai_security.generate_ai_security_brief",
               side_effect=RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate AI security brief.")):
        r = client.get(f"/api/clients/{client_id}/ai-security/posture-brief", headers=admin_user["headers"])
    assert r.status_code == 503
    assert "unavailable" in r.json()["detail"].lower()


def test_unrelated_runtime_error_still_returns_opaque_500(admin_user, client):
    """A RuntimeError that isn't about the AI key must NOT be reclassified as 503,
    and must not leak its message (could expose internals)."""
    client_id = _seed_client()
    with patch("app.api.ai_security.check_ai_library_cves", return_value=[]), \
         patch("app.api.ai_security.generate_ai_security_brief",
               side_effect=RuntimeError("some unrelated internal failure with secret path /etc/x")):
        r = client.get(f"/api/clients/{client_id}/ai-security/posture-brief", headers=admin_user["headers"])
    assert r.status_code == 500
    assert r.json()["detail"] == "Internal server error."
    assert "secret path" not in r.json()["detail"]
