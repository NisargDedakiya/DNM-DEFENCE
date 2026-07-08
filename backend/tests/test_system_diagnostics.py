from unittest.mock import patch

from app.services.system_diagnostics import (
    check_redis, check_celery_workers, check_tools, check_ai_reports_configured,
    count_stuck_scans, run_diagnostics,
)


def test_check_redis_true_on_successful_ping():
    fake_client = type("FakeRedis", (), {"ping": lambda self: True})()
    with patch("redis.Redis.from_url", return_value=fake_client):
        assert check_redis() is True


def test_check_redis_false_on_connection_error():
    with patch("redis.Redis.from_url", side_effect=ConnectionError("down")):
        assert check_redis() is False


def test_check_celery_workers_reachable():
    with patch("app.workers.celery_app.celery_app.control.ping", return_value=[{"worker1": "pong"}]):
        result = check_celery_workers()
    assert result == {"reachable": True, "worker_count": 1}


def test_check_celery_workers_unreachable_when_no_replies():
    with patch("app.workers.celery_app.celery_app.control.ping", return_value=[]):
        result = check_celery_workers()
    assert result == {"reachable": False, "worker_count": 0}


def test_check_celery_workers_unreachable_on_exception():
    with patch("app.workers.celery_app.celery_app.control.ping", side_effect=Exception("broker down")):
        result = check_celery_workers()
    assert result == {"reachable": False, "worker_count": 0}


def test_check_tools_reports_present_and_missing():
    with patch("shutil.which", side_effect=lambda name: "/usr/bin/" + name if name == "nmap" else None):
        result = check_tools(["nmap", "subfinder"])
    assert result == {"nmap": True, "subfinder": False}


def test_check_ai_reports_configured_true_for_real_key():
    with patch("app.services.system_diagnostics.settings.ANTHROPIC_API_KEY", "sk-ant-real-key-abc123"):
        assert check_ai_reports_configured() is True


def test_check_ai_reports_configured_false_for_blank_or_placeholder():
    with patch("app.services.system_diagnostics.settings.ANTHROPIC_API_KEY", ""):
        assert check_ai_reports_configured() is False
    with patch("app.services.system_diagnostics.settings.ANTHROPIC_API_KEY", "test-key-for-local-verification"):
        assert check_ai_reports_configured() is False


def test_count_stuck_scans(client):
    import uuid
    from datetime import datetime, timedelta
    from app.core.database import SessionLocal
    from app.models.models import Client, ScanRun, ScanStatus, ScanType

    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Diag Co", root_domain="diag.example.com", contact_email="a@diag.example.com")
    db.add(c)
    db.commit()
    db.add(ScanRun(client_id=c.id, scan_type=ScanType.subdomain_enum, status=ScanStatus.running,
                    started_at=datetime.utcnow() - timedelta(hours=10)))
    db.add(ScanRun(client_id=c.id, scan_type=ScanType.subdomain_enum, status=ScanStatus.running,
                    started_at=datetime.utcnow() - timedelta(minutes=5)))
    db.commit()

    assert count_stuck_scans(db) == 1
    db.close()


def test_run_diagnostics_healthy_when_everything_ok(client):
    from app.core.database import SessionLocal
    db = SessionLocal()
    with patch("app.services.system_diagnostics.check_redis", return_value=True), \
         patch("app.services.system_diagnostics.check_celery_workers", return_value={"reachable": True, "worker_count": 2}), \
         patch("app.services.system_diagnostics.check_tools", return_value={"subfinder": True, "httpx": True, "naabu": True, "nmap": True, "dig": True}), \
         patch("app.services.system_diagnostics.check_ai_reports_configured", return_value=True):
        result = run_diagnostics(db)
    db.close()
    assert result["healthy"] is True
    assert result["warnings"] == []


def test_run_diagnostics_flags_worker_unreachable(client):
    from app.core.database import SessionLocal
    db = SessionLocal()
    with patch("app.services.system_diagnostics.check_redis", return_value=True), \
         patch("app.services.system_diagnostics.check_celery_workers", return_value={"reachable": False, "worker_count": 0}), \
         patch("app.services.system_diagnostics.check_tools", return_value={"subfinder": True, "httpx": True, "naabu": True, "nmap": True, "dig": True}), \
         patch("app.services.system_diagnostics.check_ai_reports_configured", return_value=True):
        result = run_diagnostics(db)
    db.close()
    assert result["healthy"] is False
    assert any("Celery worker" in w for w in result["warnings"])


def test_run_diagnostics_flags_missing_recon_tools(client):
    from app.core.database import SessionLocal
    db = SessionLocal()
    with patch("app.services.system_diagnostics.check_redis", return_value=True), \
         patch("app.services.system_diagnostics.check_celery_workers", return_value={"reachable": True, "worker_count": 1}), \
         patch("app.services.system_diagnostics.check_tools", return_value={"subfinder": False, "httpx": True, "naabu": True, "nmap": True, "dig": True}), \
         patch("app.services.system_diagnostics.check_ai_reports_configured", return_value=True):
        result = run_diagnostics(db)
    db.close()
    assert result["healthy"] is False
    assert any("subfinder" in w for w in result["warnings"])
