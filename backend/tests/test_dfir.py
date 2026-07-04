import hashlib
from unittest.mock import MagicMock, patch

from app.models.models import DfirCase, DfirEvidence, DfirIoc, DfirTimelineEntry, Severity, DfirCaseStatus
from app.services.dfir import (
    compute_file_hashes, append_custody_entry, generate_executive_report, generate_technical_report,
    export_iocs_stix, export_iocs_sigma, export_iocs_csv,
)


def _make_case(**overrides):
    defaults = dict(id="c1", client_id="client-1", case_number="DFIR-2026-0001", incident_type="Ransomware",
                     severity=Severity.critical, status=DfirCaseStatus.active, affected_systems=["fs01", "ws02"],
                     data_exfiltrated=True)
    defaults.update(overrides)
    return DfirCase(**defaults)


def test_compute_file_hashes_matches_known_digests():
    data = b"forensic evidence bytes"
    result = compute_file_hashes(data)
    assert result["md5_hash"] == hashlib.md5(data).hexdigest()
    assert result["sha256_hash"] == hashlib.sha256(data).hexdigest()
    assert result["file_size_bytes"] == len(data)


def test_append_custody_entry_is_append_only():
    evidence = DfirEvidence(id="e1", case_id="c1", chain_of_custody=[{"timestamp": "t0", "custodian": "A", "action": "acquired"}])
    updated = append_custody_entry(evidence, "B", "transferred to lab")
    assert len(updated) == 2
    assert updated[0]["custodian"] == "A"
    assert updated[1]["custodian"] == "B"
    assert updated[1]["action"] == "transferred to lab"


def test_append_custody_entry_handles_empty_history():
    evidence = DfirEvidence(id="e1", case_id="c1", chain_of_custody=None)
    updated = append_custody_entry(evidence, "A", "acquired")
    assert len(updated) == 1


def test_generate_executive_report_grounded_in_case():
    case = _make_case()
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="Executive summary body.")]
    with patch("app.services.dfir._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        report = generate_executive_report(case)
    assert report == "Executive summary body."
    prompt = mock_client_factory.return_value.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "DFIR-2026-0001" in prompt
    assert "Ransomware" in prompt


def test_generate_technical_report_grounded_in_evidence_iocs_timeline():
    case = _make_case()
    evidence = [DfirEvidence(id="e1", case_id="c1", evidence_type="disk image", source_host="fs01", sha256_hash="abc123")]
    iocs = [DfirIoc(id="i1", case_id="c1", ioc_type="ip", value="1.2.3.4", confidence="high")]
    timeline = [DfirTimelineEntry(id="t1", case_id="c1", timestamp="2026-01-01T00:00:00", event_description="Initial compromise", host="fs01")]
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="Technical report body.")]
    with patch("app.services.dfir._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        report = generate_technical_report(case, evidence, iocs, timeline)
    assert report == "Technical report body."
    prompt = mock_client_factory.return_value.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "1.2.3.4" in prompt
    assert "Initial compromise" in prompt


def test_export_iocs_stix_produces_valid_bundle():
    iocs = [DfirIoc(id="i1", case_id="c1", ioc_type="ip", value="1.2.3.4", confidence="high")]
    bundle = export_iocs_stix(iocs)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 1
    assert "1.2.3.4" in bundle["objects"][0]["pattern"]


def test_export_iocs_stix_handles_empty_list():
    bundle = export_iocs_stix([])
    assert bundle["objects"] == []


def test_export_iocs_sigma_produces_yaml_with_values():
    import yaml
    iocs = [DfirIoc(id="i1", case_id="c1", ioc_type="ip", value="1.2.3.4", confidence="high")]
    rule_yaml = export_iocs_sigma(iocs)
    parsed = yaml.safe_load(rule_yaml)
    assert "1.2.3.4" in parsed["detection"]["selection"]["destination.ip|in"]


def test_export_iocs_csv_includes_header_and_rows():
    iocs = [DfirIoc(id="i1", case_id="c1", ioc_type="domain", value="evil.example.com", confidence="medium")]
    csv_text = export_iocs_csv(iocs)
    assert "ioc_type,value,confidence" in csv_text
    assert "evil.example.com" in csv_text
