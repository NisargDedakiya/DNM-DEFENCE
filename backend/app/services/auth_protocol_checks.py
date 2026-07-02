"""
Module 2 — Feature 2.3: Authentication & Protocol Testing.

JWT weakness detection and OAuth2/OIDC misconfiguration checks. Both are
passive/read-only probes against a client's own onboarded hosts -- no
credential brute-forcing, no destructive requests, matching the
authorized-scope posture of the rest of the platform.
"""
import base64
import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from app.models.models import Finding, Severity, FindingStatus

logger = logging.getLogger(__name__)

# Signature segment allows zero chars (not "{5,}") because a genuine
# alg:none token -- the exact case this is most valuable for catching --
# legitimately has an empty signature.
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")

# A small curated list of well-known weak/default HS256 secrets -- the same
# category of check jwt_tool's "known secrets" mode does. Bounded on
# purpose: this is meant to catch genuinely careless defaults, not to be a
# general-purpose password cracker.
COMMON_WEAK_JWT_SECRETS = [
    "secret", "password", "your-256-bit-secret", "changeme", "jwt_secret",
    "supersecret", "123456", "secretkey", "mysecret", "key", "jwtsecret",
]


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def _decode_jwt_header_payload(token: str) -> tuple[dict, dict] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload
    except (ValueError, json.JSONDecodeError):
        return None


def analyze_jwt(token: str) -> list[dict]:
    """
    Feature 2.3 — inspects a single JWT for: alg:none acceptance, missing
    expiry, and a weak/guessable HS256 signing secret. Read-only analysis
    of the token itself; the weak-secret check re-signs locally and
    compares signatures, it never sends anything to the target.
    """
    issues = []
    decoded = _decode_jwt_header_payload(token)
    if not decoded:
        return issues
    header, payload = decoded
    alg = header.get("alg", "")

    if alg.lower() == "none":
        issues.append({"issue": "jwt_alg_none", "detail": "Token header declares alg:none — if the server accepts this, signature verification can be bypassed entirely."})

    if "exp" not in payload:
        issues.append({"issue": "jwt_missing_exp", "detail": "Token has no expiry (exp) claim — it remains valid indefinitely if leaked."})

    if alg.upper().startswith("HS"):
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        given_sig = _b64url_decode(parts[2]) if len(parts) == 3 else b""
        digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg.upper(), hashlib.sha256)
        for secret in COMMON_WEAK_JWT_SECRETS:
            computed = hmac.new(secret.encode(), signing_input, digest).digest()
            if hmac.compare_digest(computed, given_sig):
                issues.append({"issue": "jwt_weak_secret", "detail": f"Token is signed with a common/guessable secret ('{secret}') — anyone can forge valid tokens."})
                break

    return issues


def discover_and_check_jwts(hosts: list[str], timeout: int = 10) -> list[dict]:
    """
    Feature 2.3 — fetches each host, scans the response body and headers
    (including Set-Cookie) for JWT-shaped strings, and analyzes any found.
    Best-effort discovery: this only catches tokens exposed in an
    unauthenticated response (e.g. a pre-filled example, a misconfigured
    debug endpoint) -- it does not attempt to log in anywhere.
    """
    findings = []
    for host in hosts:
        url = host if host.startswith("http") else f"https://{host}"
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False)
        except httpx.HTTPError:
            continue
        haystack = resp.text + " ".join(resp.headers.get_list("set-cookie")) if hasattr(resp.headers, "get_list") else resp.text
        tokens = set(JWT_PATTERN.findall(haystack))
        for token in tokens:
            issues = analyze_jwt(token)
            for issue in issues:
                findings.append({"host": host, "token_prefix": token[:16] + "...", **issue})
    return findings


def check_oauth_misconfig(hosts: list[str], timeout: int = 10) -> list[dict]:
    """
    Feature 2.3 — probes standard OIDC/OAuth2 discovery endpoints; where a
    discovery document points to an authorization endpoint, tests whether
    an arbitrary foreign redirect_uri is honored (open-redirect signal)
    without registering a client or completing any real auth flow.
    """
    findings = []
    for host in hosts:
        base = host if host.startswith("http") else f"https://{host}"
        discovery_doc = None
        for well_known in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
            try:
                resp = httpx.get(f"{base}{well_known}", timeout=timeout, verify=False)
                if resp.status_code == 200:
                    discovery_doc = resp.json()
                    break
            except (httpx.HTTPError, ValueError):
                continue
        if not discovery_doc:
            continue

        authorize_endpoint = discovery_doc.get("authorization_endpoint")
        if not authorize_endpoint:
            continue

        try:
            probe_url = f"{authorize_endpoint}?response_type=code&client_id=probe&redirect_uri=https://attacker-controlled.example.com/callback&state=x"
            resp = httpx.get(probe_url, timeout=timeout, follow_redirects=False, verify=False)
            location = resp.headers.get("location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and "attacker-controlled.example.com" in location:
                findings.append({
                    "host": host, "issue": "oauth_open_redirect",
                    "detail": f"Authorization endpoint {authorize_endpoint} redirected to an unregistered redirect_uri without validation.",
                })
        except httpx.HTTPError:
            pass

        if "code_challenge_methods_supported" not in discovery_doc:
            findings.append({
                "host": host, "issue": "oauth_no_pkce_disclosed",
                "detail": f"{authorize_endpoint} discovery document does not advertise PKCE support — verify the server requires PKCE for public clients.",
            })

    return findings


_JWT_SEVERITY = {
    "jwt_alg_none": Severity.critical,
    "jwt_weak_secret": Severity.critical,
    "jwt_missing_exp": Severity.medium,
}
_OAUTH_SEVERITY = {
    "oauth_open_redirect": Severity.high,
    "oauth_no_pkce_disclosed": Severity.low,
}


def sync_auth_protocol_findings_to_db(db: Session, client, jwt_findings: list[dict], oauth_findings: list[dict]) -> int:
    """Feature 2.3 — turns JWT/OAuth check results into real Finding rows."""
    now = datetime.utcnow()
    count = 0

    for hit in jwt_findings:
        dedup = hashlib.sha256(f"{client.id}:jwt:{hit['host']}:{hit['issue']}:{hit['token_prefix']}".encode()).hexdigest()
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        severity = _JWT_SEVERITY.get(hit["issue"], Severity.medium)
        db.add(Finding(
            client_id=client.id, title=f"JWT weakness ({hit['issue'].replace('_', ' ')}) — {hit['host']}",
            description=hit["detail"], severity=severity,
            cvss_score=9.0 if severity == Severity.critical else 5.0,
            status=FindingStatus.new, evidence=hit,
            remediation_steps="Reject alg:none tokens server-side, always set a short expiry, and use a high-entropy signing secret (32+ random bytes) or move to RS256.",
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=client.sla_hours_critical) if severity == Severity.critical else None,
        ))
        count += 1

    for hit in oauth_findings:
        dedup = hashlib.sha256(f"{client.id}:oauth:{hit['host']}:{hit['issue']}".encode()).hexdigest()
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        severity = _OAUTH_SEVERITY.get(hit["issue"], Severity.medium)
        db.add(Finding(
            client_id=client.id, title=f"OAuth2 misconfiguration ({hit['issue'].replace('_', ' ')}) — {hit['host']}",
            description=hit["detail"], severity=severity,
            cvss_score=7.0 if severity == Severity.high else 3.0,
            status=FindingStatus.new, evidence=hit,
            remediation_steps="Validate redirect_uri against a registered allow-list server-side, and require PKCE for all public clients.",
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=client.sla_hours_high) if severity == Severity.high else None,
        ))
        count += 1

    db.commit()
    return count
