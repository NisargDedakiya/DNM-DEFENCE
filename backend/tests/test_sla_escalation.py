import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

from app.core.database import SessionLocal
from app.models.models import Client, Finding, Severity, FindingStatus
from app.workers.tasks import check_sla_escalations


def _seed_overdue_finding(severity=Severity.high, escalated_at=None):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Escalation Co", root_domain="escalation.example.com",
               contact_email="a@escalation.example.com")
    db.add(c)
    db.commit()
    finding = Finding(
        id=str(uuid.uuid4()), client_id=c.id, title="Overdue finding", severity=severity,
        status=FindingStatus.new, dedup_hash=str(uuid.uuid4()),
        sla_deadline=datetime.utcnow() - timedelta(hours=5), escalated_at=escalated_at,
    )
    db.add(finding)
    db.commit()
    finding_id = finding.id
    db.close()
    return finding_id


def test_escalation_sets_count_and_timestamp_on_first_breach(client):
    finding_id = _seed_overdue_finding()
    with patch("app.workers.tasks.notifications.notify_sla_breach"), \
         patch("app.workers.tasks.draft_alert_for_finding.delay"):
        result = check_sla_escalations.run()

    assert result["newly_escalated"] == 1
    db = SessionLocal()
    f = db.query(Finding).get(finding_id)
    assert f.escalation_count == 1
    assert f.escalated_at is not None


def test_escalation_does_not_repeat_within_24_hours(client):
    recent = datetime.utcnow() - timedelta(hours=2)
    finding_id = _seed_overdue_finding(escalated_at=recent)
    db = SessionLocal()
    f = db.query(Finding).get(finding_id)
    f.escalation_count = 1
    db.commit()
    db.close()

    with patch("app.workers.tasks.notifications.notify_sla_breach") as mock_notify, \
         patch("app.workers.tasks.draft_alert_for_finding.delay"):
        result = check_sla_escalations.run()

    assert result["newly_escalated"] == 0
    mock_notify.assert_not_called()
    db = SessionLocal()
    f = db.query(Finding).get(finding_id)
    assert f.escalation_count == 1  # unchanged


def test_escalation_re_fires_after_24_hours(client):
    old = datetime.utcnow() - timedelta(hours=30)
    finding_id = _seed_overdue_finding(escalated_at=old)
    db = SessionLocal()
    f = db.query(Finding).get(finding_id)
    f.escalation_count = 1
    db.commit()
    db.close()

    with patch("app.workers.tasks.notifications.notify_sla_breach"), \
         patch("app.workers.tasks.draft_alert_for_finding.delay"):
        result = check_sla_escalations.run()

    assert result["newly_escalated"] == 1
    db = SessionLocal()
    f = db.query(Finding).get(finding_id)
    assert f.escalation_count == 2


def test_escalation_drafts_alert_for_high_and_critical_only(client):
    high_id = _seed_overdue_finding(severity=Severity.high)
    medium_id = _seed_overdue_finding(severity=Severity.medium)

    with patch("app.workers.tasks.notifications.notify_sla_breach"), \
         patch("app.workers.tasks.draft_alert_for_finding.delay") as mock_draft:
        check_sla_escalations.run()

    drafted_ids = {call.args[0] for call in mock_draft.call_args_list}
    assert high_id in drafted_ids
    assert medium_id not in drafted_ids
