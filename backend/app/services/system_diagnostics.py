"""
Module 7 / ops — live system diagnostics.

Every scan-trigger endpoint just enqueues a Celery task and returns
immediately (`task.delay(...)`) -- if nothing is actually consuming that
queue (worker not started, wrong broker URL, recon tools missing), the
failure is silent: the ScanRun sits at "running" forever and the operator
sees nothing wrong until they go digging through logs. This module answers
"is the platform actually able to do work right now?" in one call so that
failure mode is visible instead of silent.
"""
import shutil
from datetime import datetime, timedelta

from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import (
    Client, Finding, FindingStatus, ScanRun, ScanStatus, Severity,
)

STUCK_SCAN_THRESHOLD_HOURS = 6

# Core to Module 1 -- if these are missing, every recon/vuln scan silently
# returns empty results instead of real findings.
REQUIRED_RECON_TOOLS = ["subfinder", "httpx", "naabu", "nmap", "dig"]

# Deeper enrichment across the Expanded/Advanced services -- missing ones
# degrade gracefully (documented in README Prerequisites), never block core
# functionality, but are worth surfacing so an operator knows what's on.
OPTIONAL_TOOLS = [
    "amass", "checksec", "binwalk", "trufflehog", "hadolint",
    "apktool", "jadx", "kube-score", "kubesec",
]


def check_database(db: Session) -> bool:
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def check_redis() -> bool:
    try:
        import redis
        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2)
        return bool(client.ping())
    except Exception:
        return False


def check_celery_workers(timeout: float = 2.0) -> dict:
    """
    Pings any live Celery workers over the broker. An empty response means
    either no worker process is running, or it's running but can't reach
    the same broker the API is configured for (e.g. REDIS_URL pointing at
    "redis" in one process and "localhost" in the other) -- both look
    identical from here and both mean queued tasks will never run.
    """
    try:
        from app.workers.celery_app import celery_app
        replies = celery_app.control.ping(timeout=timeout)
        return {"reachable": bool(replies), "worker_count": len(replies or [])}
    except Exception:
        return {"reachable": False, "worker_count": 0}


def check_tools(tool_names: list[str]) -> dict[str, bool]:
    return {tool: shutil.which(tool) is not None for tool in tool_names}


def check_ai_reports_configured() -> bool:
    return bool(settings.ANTHROPIC_API_KEY) and settings.ANTHROPIC_API_KEY not in ("", "your-api-key-here", "test-key-for-local-verification")


def count_stuck_scans(db: Session, threshold_hours: int = STUCK_SCAN_THRESHOLD_HOURS) -> int:
    """
    Scans still "running" well past any single scan's reasonable duration --
    the surest sign that tasks are being queued but nothing is consuming
    them, since check_scan_health (the beat task that would normally flag
    these as failed) has the exact same worker/beat dependency and won't
    run either if the worker is down.
    """
    cutoff = datetime.utcnow() - timedelta(hours=threshold_hours)
    return db.query(ScanRun).filter(ScanRun.status == ScanStatus.running, ScanRun.started_at < cutoff).count()


def run_diagnostics(db: Session) -> dict:
    database_ok = check_database(db)
    redis_ok = check_redis()
    celery = check_celery_workers()
    required_tools = check_tools(REQUIRED_RECON_TOOLS)
    optional_tools = check_tools(OPTIONAL_TOOLS)
    ai_configured = check_ai_reports_configured()
    stuck_scans = count_stuck_scans(db) if database_ok else 0

    missing_required_tools = [t for t, present in required_tools.items() if not present]

    warnings = []
    if not redis_ok:
        warnings.append("Redis is unreachable — no background task (scan, report, alert) can be queued or processed.")
    if redis_ok and not celery["reachable"]:
        warnings.append("No Celery worker responded to a ping — scans will queue but never run. Start one with: celery -A app.workers.celery_app worker --loglevel=info")
    if missing_required_tools:
        warnings.append(f"Recon tools missing from PATH: {', '.join(missing_required_tools)} — scans will complete but return no real findings for the checks that depend on them.")
    if not ai_configured:
        warnings.append("ANTHROPIC_API_KEY is not set to a real key — AI-generated reports, executive summaries, and narratives will fail or return nothing.")
    if stuck_scans:
        warnings.append(f"{stuck_scans} scan(s) have been stuck in 'running' for over {STUCK_SCAN_THRESHOLD_HOURS}h — almost always means the worker isn't processing the queue.")

    healthy = database_ok and redis_ok and celery["reachable"] and not missing_required_tools

    return {
        "healthy": healthy,
        "database": {"ok": database_ok},
        "redis": {"ok": redis_ok},
        "celery": celery,
        "required_recon_tools": required_tools,
        "optional_tools": optional_tools,
        "ai_reports_configured": ai_configured,
        "stuck_scans": stuck_scans,
        "warnings": warnings,
    }


_OPEN_STATUSES = (FindingStatus.new, FindingStatus.acknowledged, FindingStatus.in_remediation, FindingStatus.disputed)


def operator_overview(db: Session) -> dict:
    """
    One 'is my whole book of business healthy right now?' rollup for the
    operator running managed security for multiple client companies -- the
    numbers you'd want on a wall dashboard. Aggregates across ALL clients
    (staff-only): client counts, open findings by severity, scan activity
    and failures, and a per-client risk leaderboard so the client needing
    attention surfaces without clicking into each one.
    """
    now = datetime.utcnow()
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    total_clients = db.query(Client).count()
    active_clients = db.query(Client).filter(Client.is_active.is_(True)).count()

    # Open findings by severity, across every client.
    sev_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.status.in_(_OPEN_STATUSES))
        .group_by(Finding.severity)
        .all()
    )
    sev_map = {s.value if hasattr(s, "value") else str(s): c for s, c in sev_rows}
    open_by_severity = {sev.value: sev_map.get(sev.value, 0) for sev in Severity}
    total_open = sum(open_by_severity.values())

    # Scan activity.
    scans_running = db.query(ScanRun).filter(ScanRun.status == ScanStatus.running).count()
    scans_completed_24h = db.query(ScanRun).filter(
        ScanRun.status == ScanStatus.completed, ScanRun.finished_at >= day_ago
    ).count()
    scans_failed_24h = db.query(ScanRun).filter(
        ScanRun.status == ScanStatus.failed, ScanRun.finished_at >= day_ago
    ).count()

    # Recent failures with enough context to act on (which client, which scan, why).
    recent_failures = []
    fail_rows = (
        db.query(ScanRun, Client.name)
        .join(Client, Client.id == ScanRun.client_id)
        .filter(ScanRun.status == ScanStatus.failed, ScanRun.finished_at >= week_ago)
        .order_by(ScanRun.finished_at.desc())
        .limit(10)
        .all()
    )
    for scan, client_name in fail_rows:
        recent_failures.append({
            "client_id": scan.client_id,
            "client_name": client_name,
            "scan_type": scan.scan_type.value if hasattr(scan.scan_type, "value") else str(scan.scan_type),
            "error": (scan.error_message or "")[:200],
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        })

    # Per-client risk leaderboard: weight open findings by severity so the
    # client with the most urgent exposure sorts to the top.
    weights = {Severity.critical: 25, Severity.high: 10, Severity.medium: 3, Severity.low: 1}
    leaderboard = []
    for client in db.query(Client).all():
        rows = (
            db.query(Finding.severity, func.count(Finding.id))
            .filter(Finding.client_id == client.id, Finding.status.in_(_OPEN_STATUSES))
            .group_by(Finding.severity)
            .all()
        )
        counts = {sev.value: 0 for sev in Severity}
        score = 0
        for sev, cnt in rows:
            key = sev.value if hasattr(sev, "value") else str(sev)
            counts[key] = cnt
            score += weights.get(sev, 0) * cnt
        leaderboard.append({
            "client_id": client.id, "client_name": client.name,
            "risk_score": min(100, score), "open_findings": sum(counts.values()),
            "critical": counts["critical"], "high": counts["high"],
        })
    leaderboard.sort(key=lambda r: r["risk_score"], reverse=True)

    diag = run_diagnostics(db)

    return {
        "generated_at": now.isoformat(),
        "system_healthy": diag["healthy"],
        "system_warnings": diag["warnings"],
        "clients": {"total": total_clients, "active": active_clients},
        "open_findings": {"total": total_open, "by_severity": open_by_severity},
        "scans": {
            "running": scans_running,
            "completed_24h": scans_completed_24h,
            "failed_24h": scans_failed_24h,
            "stuck": diag["stuck_scans"],
        },
        "recent_failures": recent_failures,
        "risk_leaderboard": leaderboard[:10],
    }
