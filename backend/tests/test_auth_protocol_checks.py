import base64
import hashlib
import hmac
import json
import uuid
from unittest.mock import patch, MagicMock

from app.core.database import SessionLocal
from app.models.models import Client, Finding
from app.services import auth_protocol_checks as apc


def _make_client(db):
    c = Client(id=str(uuid.uuid4()), name="Auth Test Co", root_domain="auth-test.example.com",
               contact_email="a@auth-test.example.com")
    db.add(c)
    db.commit()
    return c


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict, secret: str | None = None) -> str:
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    if header.get("alg", "").lower() == "none":
        sig = ""
    else:
        digest = hashlib.sha256
        sig = _b64url(hmac.new((secret or "randomsecret").encode(), signing_input, digest).digest())
    return f"{h}.{p}.{sig}"


def test_analyze_jwt_flags_alg_none():
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "user1", "exp": 9999999999})
    issues = [i["issue"] for i in apc.analyze_jwt(token)]
    assert "jwt_alg_none" in issues


def test_analyze_jwt_flags_missing_exp():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1"}, secret="totally-random-32-byte-secret-x")
    issues = [i["issue"] for i in apc.analyze_jwt(token)]
    assert "jwt_missing_exp" in issues


def test_analyze_jwt_flags_weak_secret():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "exp": 9999999999}, secret="secret")
    issues = [i["issue"] for i in apc.analyze_jwt(token)]
    assert "jwt_weak_secret" in issues


def test_analyze_jwt_clean_token_has_no_issues():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "exp": 9999999999}, secret="a-genuinely-long-random-secret-value-32b")
    assert apc.analyze_jwt(token) == []


def test_discover_and_check_jwts_finds_token_in_body():
    token = _make_jwt({"alg": "none"}, {"sub": "user1", "exp": 9999999999})
    resp = MagicMock()
    resp.text = f'<html>window.token = "{token}"</html>'
    resp.headers = MagicMock()
    resp.headers.get_list.return_value = []
    with patch("app.services.auth_protocol_checks.httpx.get", return_value=resp):
        findings = apc.discover_and_check_jwts(["leaky.example.com"])
    assert any(f["issue"] == "jwt_alg_none" for f in findings)


def test_discover_and_check_jwts_skips_unreachable_hosts():
    import httpx as httpx_module
    with patch("app.services.auth_protocol_checks.httpx.get", side_effect=httpx_module.ConnectError("refused")):
        findings = apc.discover_and_check_jwts(["unreachable.example.com"])
    assert findings == []


def test_check_oauth_misconfig_flags_open_redirect():
    discovery_resp = MagicMock()
    discovery_resp.status_code = 200
    discovery_resp.json.return_value = {
        "authorization_endpoint": "https://auth.example.com/authorize",
        "code_challenge_methods_supported": ["S256"],
    }
    redirect_resp = MagicMock()
    redirect_resp.status_code = 302
    redirect_resp.headers = {"location": "https://attacker-controlled.example.com/callback?code=abc"}

    with patch("app.services.auth_protocol_checks.httpx.get", side_effect=[discovery_resp, redirect_resp]):
        findings = apc.check_oauth_misconfig(["auth.example.com"])
    assert any(f["issue"] == "oauth_open_redirect" for f in findings)


def test_check_oauth_misconfig_flags_missing_pkce_disclosure():
    discovery_resp = MagicMock()
    discovery_resp.status_code = 200
    discovery_resp.json.return_value = {"authorization_endpoint": "https://auth.example.com/authorize"}
    safe_redirect_resp = MagicMock()
    safe_redirect_resp.status_code = 400
    safe_redirect_resp.headers = {}

    with patch("app.services.auth_protocol_checks.httpx.get", side_effect=[discovery_resp, safe_redirect_resp]):
        findings = apc.check_oauth_misconfig(["auth.example.com"])
    assert any(f["issue"] == "oauth_no_pkce_disclosed" for f in findings)


def test_check_oauth_misconfig_no_discovery_doc_returns_empty():
    resp = MagicMock()
    resp.status_code = 404
    with patch("app.services.auth_protocol_checks.httpx.get", return_value=resp):
        findings = apc.check_oauth_misconfig(["no-oidc.example.com"])
    assert findings == []


def test_sync_auth_protocol_findings_to_db(client):
    db = SessionLocal()
    c = _make_client(db)
    jwt_hits = [{"host": "web.auth-test.example.com", "token_prefix": "eyJhbGciOiJIUzI1...", "issue": "jwt_alg_none", "detail": "x"}]
    oauth_hits = [{"host": "auth.auth-test.example.com", "issue": "oauth_open_redirect", "detail": "y"}]
    count = apc.sync_auth_protocol_findings_to_db(db, c, jwt_hits, oauth_hits)
    assert count == 2
    findings = db.query(Finding).filter_by(client_id=c.id).all()
    severities = {f.title.split(" (")[0]: f.severity.value for f in findings}
    assert any(f.severity.value == "critical" for f in findings)  # jwt_alg_none
    assert any(f.severity.value == "high" for f in findings)  # oauth_open_redirect
