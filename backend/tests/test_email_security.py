from unittest.mock import patch

from app.services import dns_ssl_monitor


def _mock_dns(records_by_key: dict):
    def fake_get_dns_records(hostname, record_type="A", timeout=10):
        return records_by_key.get((hostname, record_type), [])
    return fake_get_dns_records


def test_check_email_security_flags_missing_spf_and_dmarc():
    with patch("app.services.dns_ssl_monitor.get_dns_records", side_effect=_mock_dns({})):
        issues = dns_ssl_monitor.check_email_security("nospf.example.com")
    codes = [i["issue"] for i in issues]
    assert "spf_missing" in codes
    assert "dmarc_missing" in codes
    assert "dkim_not_found_default_selector" in codes


def test_check_email_security_flags_weak_spf_policy():
    records = {
        ("goodspf.example.com", "TXT"): ['"v=spf1 include:_spf.example.com ?all"'],
        ("_dmarc.goodspf.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:x@example.com"'],
        ("default._domainkey.goodspf.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=..."'],
    }
    with patch("app.services.dns_ssl_monitor.get_dns_records", side_effect=_mock_dns(records)):
        issues = dns_ssl_monitor.check_email_security("goodspf.example.com")
    codes = [i["issue"] for i in issues]
    assert "spf_weak_policy" in codes
    assert "spf_missing" not in codes
    assert "dmarc_missing" not in codes


def test_check_email_security_flags_dmarc_policy_none():
    records = {
        ("p-none.example.com", "TXT"): ['"v=spf1 -all"'],
        ("_dmarc.p-none.example.com", "TXT"): ['"v=DMARC1; p=none"'],
        ("default._domainkey.p-none.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=..."'],
    }
    with patch("app.services.dns_ssl_monitor.get_dns_records", side_effect=_mock_dns(records)):
        issues = dns_ssl_monitor.check_email_security("p-none.example.com")
    codes = [i["issue"] for i in issues]
    assert "dmarc_policy_none" in codes


def test_check_email_security_clean_domain_has_no_issues():
    records = {
        ("clean.example.com", "TXT"): ['"v=spf1 include:_spf.example.com -all"'],
        ("_dmarc.clean.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:x@example.com"'],
        ("default._domainkey.clean.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=..."'],
    }
    with patch("app.services.dns_ssl_monitor.get_dns_records", side_effect=_mock_dns(records)):
        issues = dns_ssl_monitor.check_email_security("clean.example.com")
    assert issues == []


def test_check_email_security_flags_multiple_spf_records():
    records = {
        ("dupe.example.com", "TXT"): ['"v=spf1 -all"', '"v=spf1 include:other.com -all"'],
    }
    with patch("app.services.dns_ssl_monitor.get_dns_records", side_effect=_mock_dns(records)):
        issues = dns_ssl_monitor.check_email_security("dupe.example.com")
    codes = [i["issue"] for i in issues]
    assert "spf_multiple_records" in codes


def test_check_ssl_fleet_tiers_expiry_severity():
    with patch("app.services.dns_ssl_monitor.check_ssl_certificate") as mock_check:
        mock_check.side_effect = [
            {"hostname": "soon7.example.com", "days_remaining": 5, "expired": False, "expiring_soon": True},
            {"hostname": "soon14.example.com", "days_remaining": 10, "expired": False, "expiring_soon": True},
            {"hostname": "soon30.example.com", "days_remaining": 25, "expired": False, "expiring_soon": True},
            {"hostname": "fine.example.com", "days_remaining": 200, "expired": False, "expiring_soon": False},
        ]
        flags = dns_ssl_monitor.check_ssl_fleet(["soon7.example.com", "soon14.example.com", "soon30.example.com", "fine.example.com"])
    issues_by_host = {f["hostname"]: f["issue"] for f in flags}
    assert issues_by_host["soon7.example.com"] == "ssl_expiring_7d"
    assert issues_by_host["soon14.example.com"] == "ssl_expiring_14d"
    assert issues_by_host["soon30.example.com"] == "ssl_expiring_30d"
    assert "fine.example.com" not in issues_by_host
