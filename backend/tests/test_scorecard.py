import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import Client, Finding, Severity, FindingStatus, DeveloperScorecardSnapshot
from app.services import scorecard


def _seed_client_with_pipeline_findings(db):
    c = Client(id=str(uuid.uuid4()), name="Scorecard Co", root_domain="scorecard.example.com",
               contact_email="a@scorecard.example.com")
    db.add(c)
    db.commit()

    now = datetime.utcnow()
    db.add(Finding(id=str(uuid.uuid4()), client_id=c.id, title="[Pipeline] Security gate failed — acme/backend@main",
                    severity=Severity.high, status=FindingStatus.new, dedup_hash=str(uuid.uuid4()), created_at=now))
    db.add(Finding(id=str(uuid.uuid4()), client_id=c.id, title="[CI Scan] trivy: CVE-1234 secret leaked",
                    description="Found a secret in the codebase", severity=Severity.critical,
                    status=FindingStatus.resolved, resolved_at=now, created_at=now - timedelta(hours=10),
                    dedup_hash=str(uuid.uuid4())))
    db.add(Finding(id=str(uuid.uuid4()), client_id=c.id, title="[IaC] CKV_AWS_1: unencrypted bucket",
                    severity=Severity.medium, status=FindingStatus.new, dedup_hash=str(uuid.uuid4())))
    # unrelated finding shouldn't count toward pipeline metrics
    db.add(Finding(id=str(uuid.uuid4()), client_id=c.id, title="Unrelated web vuln",
                    severity=Severity.low, status=FindingStatus.new, dedup_hash=str(uuid.uuid4())))
    db.commit()
    return c


def test_compute_scorecard_metrics_only_counts_pipeline_sourced_findings(client):
    db = SessionLocal()
    c = _seed_client_with_pipeline_findings(db)
    metrics = scorecard.compute_scorecard_metrics(db, c.id)
    assert metrics["total_pipeline_findings"] == 3  # excludes the "Unrelated web vuln"
    assert metrics["vulnerabilities_blocked"] == 1  # only [Pipeline]-prefixed
    assert metrics["secrets_blocked"] == 1  # description mentions "secret"
    assert metrics["mttr_hours"] is not None
    assert metrics["open_pipeline_findings"] == 2


def test_snapshot_scorecard_persists_row(client):
    db = SessionLocal()
    c = _seed_client_with_pipeline_findings(db)
    snap = scorecard.snapshot_scorecard(db, c)
    assert snap.id is not None
    saved = db.query(DeveloperScorecardSnapshot).filter_by(client_id=c.id).first()
    assert saved.metrics["total_pipeline_findings"] == 3


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def test_generate_scorecard_narrative_grounds_prompt_in_real_metrics():
    fake_ai = MagicMock()
    resp = MagicMock()
    resp.content = [_text_block("Solid month overall.")]
    fake_ai.messages.create.return_value = resp

    metrics = {"pipeline_health_score": 90, "vulnerabilities_blocked": 3, "secrets_blocked": 1, "mttr_hours": 5.2, "open_pipeline_findings": 1}
    with patch.object(scorecard, "_claude_client", return_value=fake_ai):
        result = scorecard.generate_scorecard_narrative("Acme Co", metrics)

    assert result == "Solid month overall."
    prompt = fake_ai.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "90/100" in prompt
    assert "do not invent" in prompt.lower()


def test_export_scorecard_pdf_writes_real_pdf(tmp_path):
    metrics = {"pipeline_health_score": 90, "vulnerabilities_blocked": 3, "secrets_blocked": 1, "mttr_hours": 5.2}
    output_path = str(tmp_path / "scorecard.pdf")
    scorecard.export_scorecard_pdf("Acme Co", metrics, "All good.", output_path)
    with open(output_path, "rb") as f:
        assert f.read()[:4] == b"%PDF"
