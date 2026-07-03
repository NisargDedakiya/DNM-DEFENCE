import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.models.models import Client, OnChainMonitor
from app.workers.tasks import poll_all_active_onchain_monitors


def _seed_monitor(is_active=True, telegram_chat_id=None, slack_webhook_url=None):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Onchain Co", root_domain="onchain.example.com",
               contact_email="a@onchain.example.com", slack_webhook_url=slack_webhook_url)
    db.add(c)
    db.commit()
    monitor = OnChainMonitor(id=str(uuid.uuid4()), client_id=c.id, contract_address="0xabc123",
                              network="ethereum", is_active=is_active, telegram_chat_id=telegram_chat_id,
                              alert_thresholds={}, last_alerts=[])
    db.add(monitor)
    db.commit()
    ids = (c.id, monitor.id)
    db.close()
    return ids


def test_poll_task_updates_checkpoint_and_persists_alerts(client):
    client_id, monitor_id = _seed_monitor()
    fake_result = {"alerts": [{"type": "large_transfer", "note": "big transfer happened"}], "new_last_checked_block": 12345}

    with patch("app.workers.tasks.onchain_monitor_service.poll_monitor", return_value=fake_result), \
         patch("app.workers.tasks.notifications.send_slack_message") as mock_slack, \
         patch("app.workers.tasks.notifications.send_telegram_message") as mock_telegram:
        result = poll_all_active_onchain_monitors.run()

    assert result["monitors_polled"] == 1
    mock_telegram.assert_not_called()  # no telegram_chat_id set on this monitor
    mock_slack.assert_not_called()  # no slack_webhook_url set on this client

    db = SessionLocal()
    monitor = db.query(OnChainMonitor).get(monitor_id)
    assert monitor.last_checked_block == 12345
    assert monitor.last_alerts[0]["note"] == "big transfer happened"
    db.close()


def test_poll_task_routes_alerts_to_telegram_and_slack(client):
    client_id, monitor_id = _seed_monitor(telegram_chat_id="chat123", slack_webhook_url="https://hooks.slack.test/x")
    fake_result = {"alerts": [{"type": "admin_function_call", "note": "pause() called"}], "new_last_checked_block": 500}

    with patch("app.workers.tasks.onchain_monitor_service.poll_monitor", return_value=fake_result), \
         patch("app.workers.tasks.notifications.send_slack_message") as mock_slack, \
         patch("app.workers.tasks.notifications.send_telegram_message") as mock_telegram:
        poll_all_active_onchain_monitors.run()

    mock_telegram.assert_called_once()
    mock_slack.assert_called_once()
    assert "pause() called" in mock_telegram.call_args.args[1]


def test_poll_task_skips_inactive_monitors(client):
    _seed_monitor(is_active=False)
    with patch("app.workers.tasks.onchain_monitor_service.poll_monitor") as mock_poll:
        result = poll_all_active_onchain_monitors.run()
    mock_poll.assert_not_called()
    assert result["monitors_polled"] == 0
