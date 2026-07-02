from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "track1",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,          # don't lose scan jobs if a worker dies mid-scan
    worker_prefetch_multiplier=1,  # one long scan job per worker at a time
)

# Module 7 — Scheduling & Workflow Automation
celery_app.conf.beat_schedule = {
    "hourly-scan-health-check": {
        "task": "app.workers.tasks.check_scan_health",
        "schedule": crontab(minute=0),  # every hour
    },
    "hourly-sla-escalation-check": {
        "task": "app.workers.tasks.check_sla_escalations",
        "schedule": crontab(minute=30),  # every hour, offset from health check
    },
    "daily-pentest-reminder-check": {
        "task": "app.workers.tasks.pentest_reminder_check",
        "schedule": crontab(hour=8, minute=0),  # 8 AM UTC daily
    },
    "daily-subdomain-enum-all-clients": {
        "task": "app.workers.tasks.run_subdomain_enum_all_clients",
        "schedule": crontab(hour=2, minute=0),  # 2 AM UTC daily
    },
    "daily-dark-web-scan-all-clients": {
        "task": "app.workers.tasks.run_dark_web_scan_all_clients",
        "schedule": crontab(hour=4, minute=0),  # 4 AM UTC daily
    },
    "daily-dns-ssl-monitor-all-clients": {
        "task": "app.workers.tasks.check_dns_and_ssl_all_clients",
        "schedule": crontab(hour=4, minute=30),  # 4:30 AM UTC daily
    },
    "daily-metric-snapshot-all-clients": {
        "task": "app.workers.tasks.snapshot_client_metrics_all_clients",
        "schedule": crontab(hour=1, minute=0),  # 1 AM UTC daily — before other scans run
    },
    "weekly-full-vuln-scan-all-clients": {
        "task": "app.workers.tasks.run_vuln_scan_all_clients",
        "schedule": crontab(hour=3, minute=0, day_of_week=1),  # Monday 3 AM
    },
    "weekly-cloud-audit-all-clients": {
        "task": "app.workers.tasks.run_cloud_audit_all_clients",
        "schedule": crontab(hour=5, minute=0, day_of_week=1),  # Monday 5 AM
    },
    "weekly-cloud-credential-rotation-check": {
        "task": "app.workers.tasks.check_cloud_credential_rotation",
        "schedule": crontab(hour=6, minute=30, day_of_week=1),  # Monday 6:30 AM
    },
    "monthly-report-generation": {
        "task": "app.workers.tasks.generate_all_client_reports",
        "schedule": crontab(hour=6, minute=0, day_of_month=1),
    },
    "weekly-threat-digest": {
        "task": "app.workers.tasks.send_weekly_threat_digests",
        "schedule": crontab(hour=7, minute=0, day_of_week=1),  # Monday 7 AM
    },
}
