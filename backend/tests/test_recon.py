import uuid
from unittest.mock import patch, MagicMock

from app.core.database import SessionLocal
from app.models.models import Client, Finding
from app.services import recon


def _make_client(db):
    c = Client(id=str(uuid.uuid4()), name="Recon Test Co", root_domain="recon-test.example.com",
               contact_email="a@recon-test.example.com")
    db.add(c)
    db.commit()
    return c


def test_check_security_headers_flags_missing_headers():
    resp = MagicMock()
    resp.headers = {"content-type": "text/html"}  # none of the security headers present
    with patch("app.services.recon.httpx.get", return_value=resp):
        results = recon.check_security_headers(["missing-headers.example.com"])
    assert len(results) == 1
    assert results[0]["host"] == "missing-headers.example.com"
    assert set(results[0]["missing"]) == set(recon.SECURITY_HEADERS.keys())


def test_check_security_headers_no_finding_when_all_present():
    resp = MagicMock()
    resp.headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    with patch("app.services.recon.httpx.get", return_value=resp):
        results = recon.check_security_headers(["fully-configured.example.com"])
    assert results == []


def test_check_security_headers_skips_unreachable_hosts():
    import httpx as httpx_module
    with patch("app.services.recon.httpx.get", side_effect=httpx_module.ConnectError("refused")):
        results = recon.check_security_headers(["unreachable.example.com"])
    assert results == []


def test_check_cve_matches_finds_hit_when_version_in_summary():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": [
        {"id": "CVE-2019-9999", "summary": "WordPress 5.2 has an XSS vulnerability.", "cvss": 6.1},
    ]}
    with patch("app.services.recon.httpx.get", return_value=resp):
        hits = recon.check_cve_matches({"host1.example.com": ["WordPress:5.2"]})
    assert len(hits) == 1
    assert hits[0]["cve_id"] == "CVE-2019-9999"
    assert hits[0]["technology"] == "WordPress"
    assert hits[0]["version"] == "5.2"


def test_check_cve_matches_skips_entries_without_version():
    with patch("app.services.recon.httpx.get") as mock_get:
        hits = recon.check_cve_matches({"host1.example.com": ["nginx"]})  # no version suffix
    mock_get.assert_not_called()
    assert hits == []


def test_check_cve_matches_degrades_gracefully_on_api_failure():
    import httpx as httpx_module
    with patch("app.services.recon.httpx.get", side_effect=httpx_module.ConnectError("network down")):
        hits = recon.check_cve_matches({"host1.example.com": ["nginx:1.18"]})
    assert hits == []


def test_run_subdomain_bruteforce_resolves_known_hosts_only():
    import socket as socket_module

    def fake_gethostbyname(host):
        if host.startswith("www."):
            return "1.2.3.4"
        raise socket_module.gaierror("not found")

    with patch("app.services.recon.socket.gethostbyname", side_effect=fake_gethostbyname):
        found = recon.run_subdomain_bruteforce("example.com")
    assert found == ["www.example.com"]


def test_sync_new_subdomain_findings_to_db_creates_info_finding(client):
    db = SessionLocal()
    c = _make_client(db)
    count = recon.sync_new_subdomain_findings_to_db(db, c, ["new-host.recon-test.example.com"])
    assert count == 1
    finding = db.query(Finding).filter_by(client_id=c.id).first()
    assert finding.severity.value == "info"
    assert "new-host.recon-test.example.com" in finding.title


def test_sync_new_subdomain_findings_to_db_dedupes_on_rerun(client):
    db = SessionLocal()
    c = _make_client(db)
    recon.sync_new_subdomain_findings_to_db(db, c, ["dup-host.recon-test.example.com"])
    second_count = recon.sync_new_subdomain_findings_to_db(db, c, ["dup-host.recon-test.example.com"])
    assert second_count == 0
    assert db.query(Finding).filter_by(client_id=c.id).count() == 1


def test_sync_port_findings_to_db_marks_dangerous_as_high_severity(client):
    db = SessionLocal()
    c = _make_client(db)
    details = [
        {"host": "db.recon-test.example.com", "port": 3306, "dangerous": True, "service": "MySQL"},
        {"host": "web.recon-test.example.com", "port": 8080, "dangerous": False, "service": None},
    ]
    count = recon.sync_port_findings_to_db(db, c, details)
    assert count == 2
    findings = {f.evidence["port"]: f for f in db.query(Finding).filter_by(client_id=c.id).all()}
    assert findings[3306].severity.value == "high"
    assert findings[3306].sla_deadline is not None
    assert findings[8080].severity.value == "low"
    assert findings[8080].sla_deadline is None


def test_sync_header_findings_to_db_creates_one_finding_per_missing_header(client):
    db = SessionLocal()
    c = _make_client(db)
    results = [{"host": "web.recon-test.example.com", "missing": ["content-security-policy", "x-frame-options"]}]
    count = recon.sync_header_findings_to_db(db, c, results)
    assert count == 2
    assert db.query(Finding).filter_by(client_id=c.id).count() == 2


def test_sync_cve_findings_to_db_sets_cve_id_and_sla(client):
    db = SessionLocal()
    c = _make_client(db)
    hits = [{"host": "web.recon-test.example.com", "technology": "WordPress", "version": "5.2",
             "cve_id": "CVE-2019-9999", "summary": "XSS in WordPress 5.2", "cvss": 6.1}]
    count = recon.sync_cve_findings_to_db(db, c, hits)
    assert count == 1
    finding = db.query(Finding).filter_by(client_id=c.id).first()
    assert finding.cve_id == "CVE-2019-9999"
    assert finding.severity.value == "high"
    assert finding.sla_deadline is not None
