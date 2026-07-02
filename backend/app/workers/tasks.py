"""
Celery tasks. Each task owns its own DB session (never share sessions
across async task boundaries) and always records a ScanRun row so the
platform health monitor (Module 7) can detect stuck/failed jobs.
"""
import logging
from datetime import datetime, timedelta

from app.core.concurrency import try_acquire_scan_slot, release_scan_slot
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.models import (
    Client, Asset, AssetType, ScanRun, ScanStatus, ScanType, CloudAccount,
    Finding, FindingStatus, Severity, MetricSnapshot,
)
from app.services import recon, vuln_scan, threat_intel, cspm, ai_reports, notifications, pentest_scheduling, dns_ssl_monitor
from app.services.risk_score import compute_risk_score
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _draft_alerts_for_recent_critical_findings(db, client_id: str, since):
    """
    Feature 5.2 hook — after any scan syncs new findings, queue an alert
    draft for anything critical/high that's brand new (status still 'new',
    created at/after this scan started). Cheap to call after every sync
    path since it's just a filtered query, not a full re-scan.
    """
    if since is None:
        return
    candidates = db.query(Finding).filter(
        Finding.client_id == client_id,
        Finding.created_at >= since,
        Finding.status == FindingStatus.new,
        Finding.severity.in_([Severity.critical, Severity.high]),
    ).all()
    for f in candidates:
        draft_alert_for_finding.delay(f.id)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=300)
def run_subdomain_enum_for_client(self, client_id: str):
    """Feature 1.1 — Automated Subdomain Enumeration for a single client."""
    if not try_acquire_scan_slot(client_id):
        logger.info(f"Client {client_id} at max concurrent scans — retrying shortly.")
        raise self.retry(countdown=60)
    db = SessionLocal()
    scan = ScanRun(client_id=client_id, scan_type=ScanType.subdomain_enum,
                    status=ScanStatus.running, started_at=datetime.utcnow())
    db.add(scan)
    db.commit()

    try:
        client = db.query(Client).get(client_id)
        if not client:
            raise ValueError(f"Client {client_id} not found")

        subfinder_hosts = recon.run_subfinder(client.root_domain)
        amass_hosts = recon.run_amass(client.root_domain)
        hosts = sorted(set(subfinder_hosts) | set(amass_hosts))
        new_count, new_hosts = recon.sync_subdomains_to_db(db, client_id, hosts)

        # Probe liveness + tech stack on everything we found (Feature 1.3)
        tech_data = recon.run_httpx_probe(hosts)
        for asset in db.query(Asset).filter_by(client_id=client_id, asset_type=AssetType.subdomain):
            if asset.value in tech_data:
                asset.tech_stack = tech_data[asset.value]
        db.commit()

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.utcnow()
        scan.new_assets_found = new_count
        db.commit()

        if new_hosts:
            # Hook: fires Feature 1.1 "new subdomain" alert via the alert engine (Module 5.2)
            logger.info(f"[{client.name}] {new_count} new subdomains: {new_hosts}")

        return {"client_id": client_id, "total_hosts": len(hosts), "new_hosts": new_count}

    except Exception as exc:
        scan.status = ScanStatus.failed
        scan.error_message = str(exc)
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise self.retry(exc=exc)
    finally:
        release_scan_slot(client_id)
        db.close()


@celery_app.task
def run_subdomain_enum_all_clients():
    """Scheduled fan-out — queues subdomain enum for every active client (Module 7 scheduler)."""
    db = SessionLocal()
    try:
        client_ids = [c.id for c in db.query(Client).filter_by(is_active=True)]
    finally:
        db.close()
    for cid in client_ids:
        run_subdomain_enum_for_client.delay(cid)
    return {"clients_queued": len(client_ids)}


@celery_app.task(bind=True, max_retries=2, default_retry_delay=300)
def run_port_scan_for_client(self, client_id: str, full_range: bool = False):
    """Feature 1.2 — Port & Service Scanning."""
    if not try_acquire_scan_slot(client_id):
        logger.info(f"Client {client_id} at max concurrent scans — retrying shortly.")
        raise self.retry(countdown=60)
    db = SessionLocal()
    scan = ScanRun(client_id=client_id, scan_type=ScanType.port_scan,
                    status=ScanStatus.running, started_at=datetime.utcnow())
    db.add(scan)
    db.commit()

    try:
        assets = db.query(Asset).filter_by(client_id=client_id, is_alive=True).all()
        hosts = [a.value for a in assets]
        port_results = recon.run_naabu_portscan(hosts, full_range=full_range)

        # Real-tool enrichment: Nmap -sV for service/version detail on
        # hosts naabu found open ports on. Skipped if the naabu pass found
        # nothing (no point running the much-slower nmap against nothing).
        hosts_with_ports = [h for h, ports in port_results.items() if ports]
        nmap_results = recon.run_nmap_service_scan(hosts_with_ports) if hosts_with_ports else {}

        new_ports_total = 0
        dangerous_found = []
        for asset in assets:
            ports = port_results.get(asset.value, [])
            # Merge nmap's service/version data into naabu's port list where they overlap
            nmap_services = {s["port"]: s for s in nmap_results.get(asset.value, [])}
            for p in ports:
                nmap_match = nmap_services.get(p["port"])
                if nmap_match:
                    p["service_guess"] = nmap_match.get("product") or p.get("service_guess")
                    p["service_version"] = nmap_match.get("version")

            new_ports_total += recon.sync_ports_to_db(db, asset, ports)
            for p in ports:
                if p["is_dangerous"]:
                    dangerous_found.append((asset.value, p["port"], p["service_guess"]))

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.utcnow()
        scan.new_findings_found = new_ports_total
        db.commit()

        if dangerous_found:
            # Hook: Feature 1.2 "dangerous service alert" — critical severity, fires immediately
            logger.warning(f"Dangerous exposed services for client {client_id}: {dangerous_found}")

        return {"client_id": client_id, "hosts_scanned": len(hosts), "new_ports": new_ports_total}

    except Exception as exc:
        scan.status = ScanStatus.failed
        scan.error_message = str(exc)
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise self.retry(exc=exc)
    finally:
        release_scan_slot(client_id)
        db.close()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=600)
def run_vuln_scan_for_client(self, client_id: str, severity_filter: str | None = None):
    """Module 2 — Vulnerability Detection & Scoring (nuclei-based)."""
    if not try_acquire_scan_slot(client_id):
        logger.info(f"Client {client_id} at max concurrent scans — retrying shortly.")
        raise self.retry(countdown=60)
    db = SessionLocal()
    scan = ScanRun(client_id=client_id, scan_type=ScanType.vuln_scan,
                    status=ScanStatus.running, started_at=datetime.utcnow())
    db.add(scan)
    db.commit()

    try:
        client = db.query(Client).get(client_id)
        if not client:
            raise ValueError(f"Client {client_id} not found")

        live_hosts = [
            a.value for a in db.query(Asset).filter_by(
                client_id=client_id, asset_type=AssetType.subdomain, is_alive=True
            )
        ]
        if not live_hosts:
            scan.status = ScanStatus.completed
            scan.finished_at = datetime.utcnow()
            db.commit()
            return {"client_id": client_id, "message": "no live hosts to scan"}

        raw_findings = vuln_scan.run_nuclei_scan(live_hosts, severity_filter=severity_filter)
        new_count, resolved_count = vuln_scan.sync_findings_to_db(db, client, raw_findings)
        _draft_alerts_for_recent_critical_findings(db, client_id, scan.started_at)

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.utcnow()
        scan.new_findings_found = new_count
        db.commit()

        if new_count:
            logger.info(f"[{client.name}] {new_count} new findings, {resolved_count} auto-verified as resolved")

        return {"client_id": client_id, "hosts_scanned": len(live_hosts),
                "new_findings": new_count, "resolved": resolved_count}

    except Exception as exc:
        scan.status = ScanStatus.failed
        scan.error_message = str(exc)
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise self.retry(exc=exc)
    finally:
        release_scan_slot(client_id)
        db.close()


@celery_app.task
def run_vuln_scan_all_clients():
    """Scheduled fan-out — weekly full vuln scan for every active client."""
    db = SessionLocal()
    try:
        client_ids = [c.id for c in db.query(Client).filter_by(is_active=True)]
    finally:
        db.close()
    for cid in client_ids:
        run_vuln_scan_for_client.delay(cid)
    return {"clients_queued": len(client_ids)}


@celery_app.task(bind=True, max_retries=2, default_retry_delay=600)
def run_dark_web_scan_for_client(self, client_id: str):
    """Module 3 — Dark Web & Threat Intelligence Monitoring."""
    if not try_acquire_scan_slot(client_id):
        logger.info(f"Client {client_id} at max concurrent scans — retrying shortly.")
        raise self.retry(countdown=60)
    db = SessionLocal()
    scan = ScanRun(client_id=client_id, scan_type=ScanType.dark_web_scan,
                    status=ScanStatus.running, started_at=datetime.utcnow())
    db.add(scan)
    db.commit()

    try:
        client = db.query(Client).get(client_id)
        if not client:
            raise ValueError(f"Client {client_id} not found")

        breaches = threat_intel.check_hibp_breaches(client.root_domain)
        github_hits = threat_intel.check_github_secret_leaks(client.root_domain)

        ip_assets = [a.value for a in db.query(Asset).filter_by(client_id=client_id, asset_type=AssetType.ip)]
        # Also resolve A records for live subdomains -- IOC/exposure feeds
        # key on IPs, and most clients won't have AssetType.ip rows populated
        # directly, only subdomains.
        live_subdomains = [a.value for a in db.query(Asset).filter_by(
            client_id=client_id, asset_type=AssetType.subdomain, is_alive=True
        ).limit(30)]  # capped to keep the external API call volume reasonable
        resolved_ips = set(ip_assets)
        for host in live_subdomains:
            resolved_ips.update(dns_ssl_monitor.get_dns_records(host, "A"))
        resolved_ips = list(resolved_ips)[:30]

        blocklist_hits = threat_intel.check_threat_intel_blocklists(resolved_ips)
        shodan_hits = threat_intel.check_shodan(resolved_ips)
        censys_hits = threat_intel.check_censys(resolved_ips)
        abusech_hits = threat_intel.check_abusech(resolved_ips)

        new_count = threat_intel.sync_intel_findings_to_db(
            db, client, breaches, github_hits, blocklist_hits, shodan_hits, censys_hits, abusech_hits
        )
        _draft_alerts_for_recent_critical_findings(db, client_id, scan.started_at)

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.utcnow()
        scan.new_findings_found = new_count
        db.commit()

        if new_count:
            logger.warning(f"[{client.name}] {new_count} new threat-intel findings "
                            f"({len(breaches)} breaches, {len(github_hits)} github hits, {len(blocklist_hits)} blocklist hits)")

        return {"client_id": client_id, "breaches": len(breaches), "github_hits": len(github_hits),
                "blocklist_hits": len(blocklist_hits), "new_findings": new_count}

    except Exception as exc:
        scan.status = ScanStatus.failed
        scan.error_message = str(exc)
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise self.retry(exc=exc)
    finally:
        release_scan_slot(client_id)
        db.close()


@celery_app.task
def run_dark_web_scan_all_clients():
    """Scheduled fan-out — daily dark web / threat intel check for every active client."""
    db = SessionLocal()
    try:
        client_ids = [c.id for c in db.query(Client).filter_by(is_active=True)]
    finally:
        db.close()
    for cid in client_ids:
        run_dark_web_scan_for_client.delay(cid)
    return {"clients_queued": len(client_ids)}


@celery_app.task(bind=True, max_retries=2, default_retry_delay=600)
def run_cloud_audit_for_client(self, client_id: str):
    """Module 4 — Cloud Security Posture Management. Audits every active cloud account for the client."""
    if not try_acquire_scan_slot(client_id):
        logger.info(f"Client {client_id} at max concurrent scans — retrying shortly.")
        raise self.retry(countdown=60)
    db = SessionLocal()
    scan = ScanRun(client_id=client_id, scan_type=ScanType.cloud_audit,
                    status=ScanStatus.running, started_at=datetime.utcnow())
    db.add(scan)
    db.commit()

    try:
        client = db.query(Client).get(client_id)
        if not client:
            raise ValueError(f"Client {client_id} not found")

        accounts = db.query(CloudAccount).filter_by(client_id=client_id, is_active=True).all()
        if not accounts:
            scan.status = ScanStatus.completed
            scan.finished_at = datetime.utcnow()
            db.commit()
            return {"client_id": client_id, "message": "no cloud accounts registered"}

        total_new = 0
        total_drift = 0
        for account in accounts:
            raw_findings = cspm.run_cloud_audit(account)
            total_new += cspm.sync_cloud_findings_to_db(db, client, account, raw_findings)

            # Feature 4.3 — drift detection against the stored baseline
            if account.config_baseline:
                drift_events = cspm.detect_drift(account.config_baseline, raw_findings)
                if drift_events:
                    total_drift += cspm.sync_cloud_findings_to_db(db, client, account, [
                        {**e, "category": "drift"} for e in drift_events
                    ])
            account.config_baseline = cspm.snapshot_baseline(raw_findings)

            # Feature 1.4 — cloud asset discovery into the main Asset inventory (AWS only for now)
            if account.provider.value == "aws":
                discovered = cspm.discover_aws_assets(account)
                cspm.sync_cloud_assets_to_db(db, client, account, discovered)

        db.commit()
        _draft_alerts_for_recent_critical_findings(db, client_id, scan.started_at)

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.utcnow()
        scan.new_findings_found = total_new
        db.commit()

        if total_new:
            logger.warning(f"[{client.name}] {total_new} new cloud misconfiguration findings, {total_drift} drift events")

        return {"client_id": client_id, "accounts_audited": len(accounts), "new_findings": total_new}

    except Exception as exc:
        scan.status = ScanStatus.failed
        scan.error_message = str(exc)
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise self.retry(exc=exc)
    finally:
        release_scan_slot(client_id)
        db.close()


@celery_app.task
def run_cloud_audit_all_clients():
    """Scheduled fan-out — cloud posture audit for every active client."""
    db = SessionLocal()
    try:
        client_ids = [c.id for c in db.query(Client).filter_by(is_active=True)]
    finally:
        db.close()
    for cid in client_ids:
        run_cloud_audit_for_client.delay(cid)
    return {"clients_queued": len(client_ids)}


@celery_app.task(bind=True, max_retries=2, default_retry_delay=600)
def generate_report_for_client(self, client_id: str):
    """Feature 5.1 — generates the monthly report (exec summary + PDF + DOCX) for one client."""
    db = SessionLocal()
    try:
        client = db.query(Client).get(client_id)
        if not client:
            raise ValueError(f"Client {client_id} not found")
        report = ai_reports.generate_monthly_report(db, client)
        logger.info(f"[{client.name}] Monthly report generated: {report.pdf_path}")
        return {"client_id": client_id, "report_id": report.id, "risk_score": report.risk_score}
    except Exception as exc:
        logger.error(f"Report generation failed for {client_id}: {exc}")
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery_app.task
def generate_all_client_reports():
    """Scheduled — 1st of each month, generates every active client's report and queues it for review."""
    db = SessionLocal()
    try:
        client_ids = [c.id for c in db.query(Client).filter_by(is_active=True)]
    finally:
        db.close()
    for cid in client_ids:
        generate_report_for_client.delay(cid)
    return {"clients_queued": len(client_ids)}


@celery_app.task(bind=True, max_retries=2, default_retry_delay=300)
def draft_alert_for_finding(self, finding_id: str):
    """
    Feature 5.2 — drafts an alert notification for a single finding. Fired
    when a new critical/high finding is created. Only actually SENDS if
    the client has opted in (Client.auto_send_critical_alerts) AND the
    platform-wide kill switch (settings.AUTO_SEND_CRITICAL_ALERTS) is on —
    otherwise it's drafted and logged for manual review/send via the API.
    """
    db = SessionLocal()
    try:
        finding = db.query(Finding).get(finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")
        client = db.query(Client).get(finding.client_id)
        draft = ai_reports.draft_alert_notification(finding)
        logger.info(f"Alert draft ready for finding {finding_id}:\n{draft}")

        sent = False
        if settings.AUTO_SEND_CRITICAL_ALERTS and client and client.auto_send_critical_alerts:
            result = notifications.notify_finding_alert(client, finding.title, finding.severity.value, draft)
            sent = result.get("email") or result.get("slack")
            logger.info(f"Alert for finding {finding_id} auto-sent: {result}")

        return {"finding_id": finding_id, "draft": draft, "sent": sent}
    except Exception as exc:
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery_app.task
def send_weekly_threat_digests():
    """Feature 5.3 — Monday morning, generates and logs a threat digest per active client."""
    db = SessionLocal()
    try:
        clients = db.query(Client).filter_by(is_active=True).all()
        for client in clients:
            recent = (
                db.query(Finding)
                .filter(Finding.client_id == client.id)
                .order_by(Finding.created_at.desc())
                .limit(10)
                .all()
            )
            digest = ai_reports.generate_weekly_threat_digest(client, [f.title for f in recent])
            logger.info(f"[{client.name}] Weekly threat digest:\n{digest}")
            notifications.notify_weekly_digest(client, digest)
        return {"clients_processed": len(clients)}
    finally:
        db.close()


# --- Module 7 — remaining scheduling/workflow automation ---

STUCK_SCAN_THRESHOLD_HOURS = 6


@celery_app.task
def check_scan_health():
    """
    Health monitoring (Module 7): flags scans that have been "running" far
    longer than any single scan type should reasonably take — usually means
    a worker died mid-job (task_acks_late should prevent silent loss, but
    this catches anything that slips through, e.g. an external tool hang).
    """
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=STUCK_SCAN_THRESHOLD_HOURS)
        stuck = db.query(ScanRun).filter(
            ScanRun.status == ScanStatus.running, ScanRun.started_at < cutoff
        ).all()
        for scan in stuck:
            scan.status = ScanStatus.failed
            scan.error_message = f"Marked failed by health monitor — exceeded {STUCK_SCAN_THRESHOLD_HOURS}h without completing."
            logger.error(f"Stuck scan detected: {scan.id} ({scan.scan_type.value}) for client {scan.client_id}")
        db.commit()

        recent_failures = db.query(ScanRun).filter(
            ScanRun.status == ScanStatus.failed, ScanRun.finished_at > datetime.utcnow() - timedelta(hours=24)
        ).count()

        return {"stuck_scans_flagged": len(stuck), "failures_last_24h": recent_failures}
    finally:
        db.close()


@celery_app.task
def check_sla_escalations():
    """
    SLA enforcement (Module 7 / Feature 2.4): findings whose sla_deadline
    has passed while still open get flagged for escalation. Actual paging/
    Slack alerting isn't wired yet — this task is the detection half; hook
    a notification send where marked below once delivery exists.
    """
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        overdue = db.query(Finding).filter(
            Finding.sla_deadline < now,
            Finding.status.notin_([FindingStatus.resolved, FindingStatus.verified]),
        ).all()

        for f in overdue:
            logger.warning(
                f"SLA BREACH: finding {f.id} ('{f.title}', {f.severity.value}) for client {f.client_id} "
                f"was due {f.sla_deadline}, still status={f.status.value}"
            )
            client = db.query(Client).get(f.client_id)
            if client:
                notifications.notify_sla_breach(client, f.title, f.severity.value, f.sla_deadline)

        return {"overdue_findings": len(overdue)}
    finally:
        db.close()


@celery_app.task
def pentest_reminder_check():
    """
    Module 7 — daily check: sends a reminder 14 days before any client's
    next scheduled pentest, and flags anything past due as overdue.
    """
    db = SessionLocal()
    try:
        result = pentest_scheduling.check_and_send_reminders(db)
        if result["reminders_sent"] or result["newly_overdue"]:
            logger.info(f"Pentest scheduling check: {result}")
        return result
    finally:
        db.close()


@celery_app.task
def check_dns_and_ssl_for_client(client_id: str):
    """
    DNS drift + SSL certificate monitoring (audit-flagged gap). DNS
    baseline is stored on Client.dns_baseline; a changed A/NS record is
    flagged critical (possible hijack), SSL issues are flagged
    medium/high depending on expired vs. expiring-soon.
    """
    import hashlib
    db = SessionLocal()
    try:
        client = db.query(Client).get(client_id)
        if not client:
            return {"message": "client not found"}

        dns_result = dns_ssl_monitor.check_dns_drift(client.root_domain, client.dns_baseline or {})
        live_hosts = [a.value for a in db.query(Asset).filter_by(client_id=client_id, asset_type=AssetType.subdomain, is_alive=True)]
        ssl_flags = dns_ssl_monitor.check_ssl_fleet(live_hosts[:50])  # cap to avoid a huge fleet blowing the task timeout

        now = datetime.utcnow()
        new_count = 0

        if dns_result["changed"] and client.dns_baseline:  # only flag drift after a baseline exists, not on first run
            for rtype, change in dns_result["diff"].items():
                dedup = hashlib.sha256(f"{client_id}:dns_drift:{rtype}:{now.date()}".encode()).hexdigest()
                if not db.query(Finding).filter_by(dedup_hash=dedup).first():
                    db.add(Finding(
                        client_id=client_id, title=f"DNS {rtype} record changed for {client.root_domain}",
                        description=f"Previous: {change['previous']}. Current: {change['current']}. Unexpected DNS changes can indicate hijacking.",
                        severity=Severity.critical if rtype in ("A", "NS") else Severity.medium,
                        cvss_score=8.5 if rtype in ("A", "NS") else 4.0, status=FindingStatus.new,
                        evidence=change, remediation_steps="Verify this change was authorized with your DNS provider immediately.",
                        dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=client.sla_hours_critical),
                    ))
                    new_count += 1

        for flag in ssl_flags:
            dedup = hashlib.sha256(f"{client_id}:{flag['issue']}:{flag['hostname']}:{now.date()}".encode()).hexdigest()
            if not db.query(Finding).filter_by(dedup_hash=dedup).first():
                severity = Severity.high if flag["issue"] in ("ssl_expired", "ssl_unreachable") else Severity.medium
                db.add(Finding(
                    client_id=client_id, title=f"[SSL] {flag['issue'].replace('_', ' ')} — {flag['hostname']}",
                    description=flag["detail"], severity=severity, cvss_score=6.0 if severity == Severity.high else 4.0,
                    status=FindingStatus.new, evidence=flag,
                    remediation_steps="Renew the certificate before expiry, or investigate why the host is unreachable over TLS.",
                    dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=client.sla_hours_high),
                ))
                new_count += 1

        client.dns_baseline = dns_result["current"]
        db.commit()

        return {"client_id": client_id, "dns_changed": dns_result["changed"], "ssl_issues": len(ssl_flags), "new_findings": new_count}
    finally:
        db.close()


@celery_app.task
def check_cloud_credential_rotation():
    """
    API key rotation (audit-flagged gap). Doesn't rotate automatically
    (that requires provider-specific IAM automation the client would need
    to authorize separately) — flags any cloud account whose credentials
    haven't been rotated within the configured window so a human does it.
    """
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=settings.CLOUD_CREDENTIAL_ROTATION_DAYS)
        stale = db.query(CloudAccount).filter(
            CloudAccount.is_active == True,  # noqa: E712
            CloudAccount.credentials_rotated_at < cutoff,
        ).all()
        for account in stale:
            client = db.query(Client).get(account.client_id)
            if client:
                logger.warning(f"Cloud credentials for {client.name} ({account.provider.value}) "
                                f"haven't been rotated since {account.credentials_rotated_at} — flagging for rotation.")
        return {"stale_credential_accounts": len(stale)}
    finally:
        db.close()


@celery_app.task
def check_dns_and_ssl_all_clients():
    """Scheduled fan-out — queues DNS/SSL monitoring for every active client (Module 7 scheduler)."""
    db = SessionLocal()
    try:
        client_ids = [c.id for c in db.query(Client).filter_by(is_active=True)]
    finally:
        db.close()
    for cid in client_ids:
        check_dns_and_ssl_for_client.delay(cid)
    return {"clients_queued": len(client_ids)}


@celery_app.task
def snapshot_client_metrics_all_clients():
    """
    Daily rollup: one MetricSnapshot row per active client, recording
    open-finding counts by severity and the current risk score. Backing
    data for every trend chart in the spec (dashboard, findings, reports) —
    written once here instead of each surface recomputing history itself.
    """
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        clients = db.query(Client).filter_by(is_active=True).all()
        written = 0
        for client in clients:
            open_findings = db.query(Finding).filter(
                Finding.client_id == client.id,
                Finding.status.notin_([FindingStatus.resolved, FindingStatus.verified]),
            ).all()
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in open_findings:
                if f.severity.value in counts:
                    counts[f.severity.value] += 1
            db.add(MetricSnapshot(
                client_id=client.id, snapshot_date=now,
                critical_count=counts["critical"], high_count=counts["high"],
                medium_count=counts["medium"], low_count=counts["low"],
                risk_score=compute_risk_score(counts),
            ))
            written += 1
        db.commit()
        return {"snapshots_written": written}
    finally:
        db.close()
