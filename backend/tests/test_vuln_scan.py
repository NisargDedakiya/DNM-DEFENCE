import uuid

from app.models.models import Client, Asset, AssetType, Severity
from app.services import vuln_scan


def _client(sla_critical=24, sla_high=72):
    return Client(id=str(uuid.uuid4()), name="Vuln Co", root_domain="vuln.example.com",
                  contact_email="a@vuln.example.com", sla_hours_critical=sla_critical, sla_hours_high=sla_high)


def _raw_nuclei_finding(host="web.vuln.example.com", severity="high", cvss=None, cvss_vector=None):
    classification = {}
    if cvss is not None:
        classification["cvss-score"] = cvss
    if cvss_vector is not None:
        classification["cvss-metrics"] = cvss_vector
    return {
        "template-id": "test-template", "host": f"https://{host}",
        "matched-at": f"https://{host}/",
        "info": {"name": "Test Finding", "severity": severity, "classification": classification},
    }


def test_parse_nuclei_finding_uses_internet_facing_by_default():
    client = _client()
    raw = _raw_nuclei_finding(cvss=8.0)
    kwargs = vuln_scan.parse_nuclei_finding(client, raw, asset_by_host={})
    assert kwargs["cvss_score"] == 8.0  # 1.0 multiplier, unchanged


def test_parse_nuclei_finding_discounts_internal_assets():
    client = _client()
    asset = Asset(id=str(uuid.uuid4()), client_id=client.id, asset_type=AssetType.subdomain,
                  value="web.vuln.example.com", is_internal=True)
    raw = _raw_nuclei_finding(cvss=8.0)
    kwargs = vuln_scan.parse_nuclei_finding(client, raw, asset_by_host={"web.vuln.example.com": asset})
    assert kwargs["cvss_score"] == 4.8  # 8.0 * 0.6


def test_parse_nuclei_finding_no_discount_for_explicitly_external_asset():
    client = _client()
    asset = Asset(id=str(uuid.uuid4()), client_id=client.id, asset_type=AssetType.subdomain,
                  value="web.vuln.example.com", is_internal=False)
    raw = _raw_nuclei_finding(cvss=8.0)
    kwargs = vuln_scan.parse_nuclei_finding(client, raw, asset_by_host={"web.vuln.example.com": asset})
    assert kwargs["cvss_score"] == 8.0


def test_parse_nuclei_finding_uses_template_cvss_vector_when_present():
    client = _client()
    raw = _raw_nuclei_finding(cvss=7.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    kwargs = vuln_scan.parse_nuclei_finding(client, raw, asset_by_host={})
    assert kwargs["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def test_parse_nuclei_finding_falls_back_to_default_vector_by_severity():
    client = _client()
    raw = _raw_nuclei_finding(severity="critical", cvss=9.8)
    kwargs = vuln_scan.parse_nuclei_finding(client, raw, asset_by_host={})
    assert kwargs["cvss_vector"] == vuln_scan.DEFAULT_CVSS_VECTOR_BY_SEVERITY[Severity.critical]


def test_run_nuclei_default_logins_scan_passes_correct_template_flag(monkeypatch):
    captured = {}

    def fake_run_nuclei_scan(targets, severity_filter=None, templates=None, timeout=1800):
        captured["templates"] = templates
        return []

    monkeypatch.setattr(vuln_scan, "run_nuclei_scan", fake_run_nuclei_scan)
    vuln_scan.run_nuclei_default_logins_scan(["web.vuln.example.com"])
    assert captured["templates"] == "default-logins/"
