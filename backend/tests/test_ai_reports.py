import os
import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import (
    Client, Finding, Severity, FindingStatus, MetricSnapshot,
    ComplianceControl, ComplianceFramework, ComplianceControlStatus,
)
from app.services import ai_reports


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _fake_claude_response(text="Mocked AI text."):
    resp = MagicMock()
    resp.content = [_text_block(text)]
    return resp


def _seed_client_with_data(db, with_compliance=True, with_snapshots=True):
    client = Client(id=str(uuid.uuid4()), name="Report Test Co", root_domain="report-test.example.com",
                     contact_email="a@report-test.example.com", brand_color="#ff5500")
    db.add(client)
    db.commit()

    db.add(Finding(id=str(uuid.uuid4()), client_id=client.id, title="Critical issue",
                    severity=Severity.critical, cvss_score=9.5, status=FindingStatus.new, dedup_hash=str(uuid.uuid4())))
    db.add(Finding(id=str(uuid.uuid4()), client_id=client.id, title="High issue",
                    severity=Severity.high, cvss_score=7.0, status=FindingStatus.acknowledged, dedup_hash=str(uuid.uuid4())))

    if with_compliance:
        db.add(ComplianceControl(id=str(uuid.uuid4()), client_id=client.id, framework=ComplianceFramework.soc2,
                                  control_id="CC1.1", control_name="Test control",
                                  status=ComplianceControlStatus.implemented))
        db.add(ComplianceControl(id=str(uuid.uuid4()), client_id=client.id, framework=ComplianceFramework.soc2,
                                  control_id="CC6.1", control_name="Test control 2",
                                  status=ComplianceControlStatus.missing))

    if with_snapshots:
        now = datetime.utcnow()
        db.add(MetricSnapshot(id=str(uuid.uuid4()), client_id=client.id, snapshot_date=now - timedelta(days=30),
                               critical_count=2, high_count=1, medium_count=0, low_count=0, risk_score=60))
        db.add(MetricSnapshot(id=str(uuid.uuid4()), client_id=client.id, snapshot_date=now - timedelta(days=1),
                               critical_count=1, high_count=1, medium_count=0, low_count=0, risk_score=35))

    db.commit()
    return client.id


def test_generate_compliance_summary_reflects_real_control_data(client):
    db = SessionLocal()
    client_id = _seed_client_with_data(db, with_compliance=True, with_snapshots=False)
    client = db.query(Client).get(client_id)
    summary_text = ai_reports.generate_compliance_summary(db, client)
    assert "SOC 2" in summary_text
    assert "50%" in summary_text  # 1 of 2 implemented
    assert "not yet configured" not in summary_text  # the old placeholder text must be gone


def test_generate_compliance_summary_placeholder_when_no_controls_seeded(client):
    db = SessionLocal()
    client = Client(id=str(uuid.uuid4()), name="No Compliance Co", root_domain="nc.example.com", contact_email="a@nc.example.com")
    db.add(client)
    db.commit()
    summary_text = ai_reports.generate_compliance_summary(db, client)
    assert "not yet configured" in summary_text


def test_generate_risk_trend_chart_returns_none_with_insufficient_data():
    assert ai_reports.generate_risk_trend_chart([]) is None
    single = MetricSnapshot(risk_score=50, snapshot_date=datetime.utcnow())
    assert ai_reports.generate_risk_trend_chart([single]) is None


def test_generate_risk_trend_chart_returns_valid_png_bytes():
    snapshots = [
        MetricSnapshot(risk_score=60, snapshot_date=datetime.utcnow() - timedelta(days=10)),
        MetricSnapshot(risk_score=35, snapshot_date=datetime.utcnow()),
    ]
    png_bytes = ai_reports.generate_risk_trend_chart(snapshots)
    assert png_bytes is not None
    assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"  # real PNG magic bytes, not a stub


def test_generate_monthly_report_end_to_end(tmp_path, monkeypatch, client):
    """Full pipeline with Claude mocked -- confirms real PDF/DOCX get written with real compliance data and a trend chart."""
    monkeypatch.setattr(ai_reports, "OUTPUT_DIR", str(tmp_path))
    db = SessionLocal()
    client_id = _seed_client_with_data(db, with_compliance=True, with_snapshots=True)
    client = db.query(Client).get(client_id)

    fake_client = MagicMock()
    fake_client.messages.create.return_value = _fake_claude_response("A mocked executive summary paragraph.")

    with patch.object(ai_reports, "_claude_client", return_value=fake_client):
        report = ai_reports.generate_monthly_report(db, client)

    assert os.path.exists(report.pdf_path)
    assert os.path.getsize(report.pdf_path) > 0
    assert os.path.exists(report.docx_path)
    assert os.path.getsize(report.docx_path) > 0
    assert report.risk_score is not None

    with open(report.pdf_path, "rb") as f:
        pdf_bytes = f.read()
    assert pdf_bytes[:4] == b"%PDF"  # real PDF, not an empty/broken file


def test_generate_weekly_threat_digest_grounds_prompt_in_real_data(client):
    fake_client = MagicMock()
    fake_client.messages.create.return_value = _fake_claude_response("Digest body.")

    test_client = Client(id=str(uuid.uuid4()), name="Digest Co", industry="fintech")
    cve_hits = [{"cve_id": "CVE-2024-1234", "technology": "WordPress", "version": "5.2", "host": "web.digest.example.com"}]
    threat_intel_hits = [{"note": "IP flagged on Emerging Threats compromised-ips list", "ip": "1.2.3.4"}]

    with patch.object(ai_reports, "_claude_client", return_value=fake_client):
        ai_reports.generate_weekly_threat_digest(test_client, ["Some finding"], cve_hits, threat_intel_hits)

    prompt = fake_client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "CVE-2024-1234" in prompt
    assert "Emerging Threats" in prompt
    assert "do not invent, recall, or reference any CVEs" in prompt


def test_generate_weekly_threat_digest_honest_when_quiet_week(client):
    fake_client = MagicMock()
    fake_client.messages.create.return_value = _fake_claude_response("Quiet week digest.")

    test_client = Client(id=str(uuid.uuid4()), name="Quiet Co", industry="fintech")
    with patch.object(ai_reports, "_claude_client", return_value=fake_client):
        ai_reports.generate_weekly_threat_digest(test_client, [], [], [])

    prompt = fake_client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "genuinely quiet" in prompt
