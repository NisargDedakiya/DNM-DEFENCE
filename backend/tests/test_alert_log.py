import uuid

from app.core.database import SessionLocal
from app.models.models import AlertLog, Client
from app.services.notifications import log_alert, export_alert_log_csv


def _seed_client(db):
    c = Client(id=str(uuid.uuid4()), name="Alert Log Co", root_domain="alertlog.example.com",
               contact_email="a@alertlog.example.com")
    db.add(c)
    db.commit()
    return c


def test_log_alert_persists_channel_flags(client):
    db = SessionLocal()
    c = _seed_client(db)
    finding_id = str(uuid.uuid4())
    entry = log_alert(db, c.id, "finding_alert", "[CRITICAL] Security alert — Exposed S3 bucket",
                       {"email": True, "slack": False}, finding_id=finding_id)
    entry_id = entry.id
    db.close()

    db = SessionLocal()
    stored = db.query(AlertLog).get(entry_id)
    assert stored.alert_type == "finding_alert"
    assert stored.channel_email_sent is True
    assert stored.channel_slack_sent is False
    assert stored.subject == "[CRITICAL] Security alert — Exposed S3 bucket"
    db.close()


def test_log_alert_handles_no_finding_id(client):
    db = SessionLocal()
    c = _seed_client(db)
    entry = log_alert(db, c.id, "weekly_threat_digest", "Weekly Threat Digest — Alert Log Co", {"email": False, "slack": True})
    entry_id = entry.id
    db.close()

    db = SessionLocal()
    stored = db.query(AlertLog).get(entry_id)
    assert stored.finding_id is None
    assert stored.channel_slack_sent is True
    db.close()


def test_export_alert_log_csv_includes_header_and_rows(client):
    db = SessionLocal()
    c = _seed_client(db)
    log_alert(db, c.id, "sla_breach", "[SLA BREACH] Overdue finding", {"email": True, "slack": True})
    entries = db.query(AlertLog).filter_by(client_id=c.id).all()
    csv_text = export_alert_log_csv(entries)
    db.close()

    assert "sent_at,alert_type,subject" in csv_text
    assert "sla_breach" in csv_text
    assert "[SLA BREACH] Overdue finding" in csv_text


def test_export_alert_log_csv_handles_empty_list():
    assert export_alert_log_csv([]) == "sent_at,alert_type,subject,finding_id,email_sent,slack_sent\r\n"
