import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.models.models import Client, DeveloperScorecardSnapshot
from app.workers.tasks import snapshot_developer_scorecards_all_clients, send_weekly_triage_digests


def _make_active_client(db):
    c = Client(id=str(uuid.uuid4()), name="Task Co", root_domain="task.example.com",
               contact_email="a@task.example.com", is_active=True)
    db.add(c)
    db.commit()
    return c


def test_snapshot_developer_scorecards_all_clients_writes_one_row_per_active_client(client):
    db = SessionLocal()
    _make_active_client(db)
    _make_active_client(db)

    result = snapshot_developer_scorecards_all_clients.run()
    assert result["snapshots_written"] == 2

    db2 = SessionLocal()
    assert db2.query(DeveloperScorecardSnapshot).count() == 2


def test_send_weekly_triage_digests_processes_all_active_clients(client):
    db = SessionLocal()
    _make_active_client(db)

    fake_ai_text = "Digest body."
    with patch("app.workers.tasks.triage_service.generate_weekly_triage_digest", return_value=fake_ai_text) as mock_digest, \
         patch("app.workers.tasks.notifications.notify_weekly_digest") as mock_notify:
        result = send_weekly_triage_digests.run()

    assert result["clients_processed"] == 1
    mock_digest.assert_called_once()
    mock_notify.assert_called_once()
