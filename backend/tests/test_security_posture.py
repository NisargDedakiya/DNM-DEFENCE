import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.core.auth import hash_password, create_access_token
from app.models.models import Client, User, UserRole, Finding, Severity, FindingStatus
from app.services.security_posture import compute_posture, _classify_domain, _score_to_grade


def _seed_client(with_findings=None):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Startup Co", root_domain="startup.example.com",
               contact_email="a@startup.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    for sev, title, status in (with_findings or []):
        db.add(Finding(client_id=cid, title=title, severity=sev, status=status, dedup_hash=uuid.uuid4().hex))
    db.commit()
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


def test_score_to_grade_bands():
    assert _score_to_grade(95) == "A"
    assert _score_to_grade(85) == "B"
    assert _score_to_grade(72) == "C"
    assert _score_to_grade(61) == "D"
    assert _score_to_grade(40) == "F"


def test_classify_domain_buckets_by_keyword():
    def f(title):
        return Finding(title=title, description="", severity=Severity.low)
    assert _classify_domain(f("Missing DMARC record")) == "Email security (phishing/spoofing)"
    assert _classify_domain(f("Public S3 bucket exposed")) == "Cloud security"
    assert _classify_domain(f("SSL certificate expired")) == "Encryption & certificates"
    assert _classify_domain(f("New open port 3389 (RDP)")) == "Exposed services & attack surface"
    assert _classify_domain(f("AWS secret key leaked in repo")) == "Exposed secrets & credentials"


def test_clean_client_gets_grade_a(client):
    cid = _seed_client()  # a scan will be counted as 0; still gradeable
    posture = None
    db = SessionLocal()
    from app.models.models import ScanRun, ScanType, ScanStatus
    db.add(ScanRun(client_id=cid, scan_type=ScanType.subdomain_enum, status=ScanStatus.completed))
    db.commit()
    db.close()
    db = SessionLocal()
    posture = compute_posture(db, cid)
    db.close()
    assert posture["grade"] == "A"
    assert posture["score"] == 100
    assert posture["assessment_ready"] is True
    assert posture["action_plan"] == []


def test_critical_finding_tanks_grade_and_leads_action_plan(client):
    cid = _seed_client([
        (Severity.critical, "Exposed production database on port 5432", FindingStatus.new),
        (Severity.high, "Missing SPF record", FindingStatus.new),
        (Severity.low, "Missing X-Frame-Options header", FindingStatus.new),
    ])
    db = SessionLocal()
    posture = compute_posture(db, cid)
    db.close()
    # 25 + 12 + 1 = 38 penalty -> 62 -> D
    assert posture["score"] == 62
    assert posture["grade"] == "D"
    # Highest severity leads the plan and carries a fix.
    assert posture["action_plan"][0]["severity"] == "critical"
    assert posture["action_plan"][0]["how_to_fix"]
    assert posture["action_plan"][0]["priority"] == 1
    # Weakest domain surfaces first.
    assert posture["domains"][0]["open_findings"] >= 1


def test_resolved_findings_excluded_from_posture(client):
    cid = _seed_client([
        (Severity.critical, "Old critical now fixed", FindingStatus.resolved),
        (Severity.low, "Minor open issue", FindingStatus.new),
    ])
    db = SessionLocal()
    posture = compute_posture(db, cid)
    db.close()
    assert posture["open_findings_total"] == 1
    assert posture["open_by_severity"]["critical"] == 0


def test_posture_endpoint_client_visible_and_shaped(client):
    cid = _seed_client([(Severity.high, "Missing DMARC record", FindingStatus.new)])
    headers = _client_headers(cid)
    with patch("app.api.posture.generate_posture_summary", return_value=None):
        r = client.get(f"/api/clients/{cid}/posture", headers=headers)
    assert r.status_code == 200
    body = r.json()
    for key in ("grade", "score", "grade_meaning", "domains", "action_plan", "soc2_readiness"):
        assert key in body


def test_posture_endpoint_tenant_isolated(client):
    cid_a = _seed_client()
    cid_b = _seed_client()
    headers_a = _client_headers(cid_a)
    r = client.get(f"/api/clients/{cid_b}/posture", headers=headers_a)
    assert r.status_code == 403
