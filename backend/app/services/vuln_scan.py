"""
Module 2 — Vulnerability Detection & Scoring.

Wraps nuclei (template-based vuln scanning) as a subprocess, maps results
into Finding rows with severity/CVSS, and deduplicates so the same issue
found on multiple assets doesn't create noise.

Install nuclei:
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    nuclei -update-templates

Scope discipline: only ever pass hosts belonging to the client whose scan
this is. Never construct target lists from anything other than the Asset
table for that client_id.
"""
import hashlib
import json
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy.orm import Session

from app.models.models import Finding, Severity, FindingStatus, Client, Asset

logger = logging.getLogger(__name__)

# nuclei severities map directly onto ours
SEVERITY_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "unknown": Severity.info,
}

# Rough CVSS midpoints per severity band, used only when nuclei doesn't
# supply a cvss-score in the template metadata.
DEFAULT_CVSS_BY_SEVERITY = {
    Severity.critical: 9.5,
    Severity.high: 7.5,
    Severity.medium: 5.0,
    Severity.low: 2.5,
    Severity.info: 0.0,
}

# Business-context multiplier (Feature 2.1): internet-facing prod assets
# are scored as-is; anything flagged internal/dev gets a discount so the
# dashboard reflects real business risk rather than raw scanner output.
CONTEXT_MULTIPLIER = {
    "internet_facing_prod": 1.0,
    "internal_or_dev": 0.6,
}

# Fallback CVSS v3.1 vector strings by severity band, used when nuclei's
# template metadata doesn't carry one -- gives a plausible vector for
# display/enrichment (attack vector/complexity/privileges/user interaction)
# rather than leaving the field blank.
DEFAULT_CVSS_VECTOR_BY_SEVERITY = {
    Severity.critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Severity.high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    Severity.medium: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
    Severity.low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    Severity.info: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}


def _default_cvss_vector(severity: Severity) -> str:
    return DEFAULT_CVSS_VECTOR_BY_SEVERITY[severity]


def run_nuclei_scan(targets: Iterable[str], severity_filter: str | None = None, templates: str | None = None, timeout: int = 1800) -> list[dict]:
    """
    Runs nuclei against a list of live hosts/URLs. Returns parsed JSON
    findings. severity_filter e.g. "critical,high" narrows the template set
    for faster/cheaper scans on a daily cadence. templates e.g.
    "default-logins/" restricts to a specific template category (see
    run_nuclei_default_logins_scan).
    """
    targets = list(targets)
    if not targets:
        return []

    cmd = ["nuclei", "-silent", "-jsonl", "-rate-limit", "50"]
    if severity_filter:
        cmd += ["-severity", severity_filter]
    if templates:
        cmd += ["-t", templates]

    try:
        proc = subprocess.run(
            cmd, input="\n".join(targets), capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.warning("nuclei binary not found on PATH — skipping vuln scan")
        return []
    except subprocess.TimeoutExpired:
        logger.error("nuclei scan timed out")
        return []

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def _dedup_hash(client_id: str, template_id: str, matched_at: str) -> str:
    """
    A finding is 'the same' if it's the same client + same vuln template +
    same host — regardless of scan run. This is what Feature 2.1's
    deduplication engine keys off, and it's also how we detect
    fix-verification (finding disappears on re-scan → auto-resolve it).
    """
    raw = f"{client_id}:{template_id}:{matched_at}"
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_nuclei_finding(client: Client, raw: dict, asset_by_host: dict[str, Asset]) -> dict:
    """Converts one raw nuclei JSON result into Finding constructor kwargs."""
    info = raw.get("info", {})
    template_id = raw.get("template-id", "unknown")
    matched_at = raw.get("matched-at", raw.get("host", ""))
    host = raw.get("host", "").replace("https://", "").replace("http://", "").split("/")[0]

    severity = SEVERITY_MAP.get(info.get("severity", "unknown"), Severity.info)
    cvss = info.get("classification", {}).get("cvss-score")
    cve_id = None
    cve_list = info.get("classification", {}).get("cve-id")
    if cve_list:
        cve_id = cve_list[0] if isinstance(cve_list, list) else cve_list

    if cvss is None:
        cvss = DEFAULT_CVSS_BY_SEVERITY[severity]

    asset = asset_by_host.get(host)
    # Feature 2.1 business-context scoring: an asset explicitly tagged
    # internal/dev (Asset.is_internal) gets the discount; anything else
    # (including unknown assets, since they were reachable enough to scan)
    # is treated as internet-facing prod, the conservative default.
    context = "internal_or_dev" if (asset and asset.is_internal) else "internet_facing_prod"
    adjusted_cvss = round(cvss * CONTEXT_MULTIPLIER[context], 1)

    cvss_vector = info.get("classification", {}).get("cvss-metrics")
    if not cvss_vector:
        cvss_vector = _default_cvss_vector(severity)

    sla_hours = {
        Severity.critical: client.sla_hours_critical,
        Severity.high: client.sla_hours_high,
    }.get(severity, 168)  # default 7-day SLA for medium/low

    return dict(
        client_id=client.id,
        asset_id=asset.id if asset else None,
        title=info.get("name", template_id),
        description=info.get("description", ""),
        severity=severity,
        cvss_score=adjusted_cvss,
        cvss_vector=cvss_vector,
        cve_id=cve_id,
        status=FindingStatus.new,
        evidence={
            "template_id": template_id,
            "matched_at": matched_at,
            "extracted": raw.get("extracted-results", []),
            "curl_command": raw.get("curl-command"),
        },
        remediation_steps=info.get("remediation", "Review the finding details and apply the relevant vendor patch or configuration fix."),
        dedup_hash=_dedup_hash(client.id, template_id, matched_at),
        sla_deadline=datetime.utcnow() + timedelta(hours=sla_hours),
    )


def sync_findings_to_db(db: Session, client: Client, raw_findings: list[dict]) -> tuple[int, int]:
    """
    Upserts nuclei findings. Returns (new_count, verified_resolved_count).

    Re-scan verification (Feature 2.4): any prior 'in_remediation' finding
    whose dedup_hash does NOT appear in this run's results gets marked
    verified/resolved automatically — this is how "client marks fixed,
    platform re-scans to confirm" works under the hood.
    """
    assets = db.query(Asset).filter_by(client_id=client.id).all()
    asset_by_host = {a.value: a for a in assets}

    seen_hashes = set()
    new_count = 0
    now = datetime.utcnow()

    for raw in raw_findings:
        kwargs = parse_nuclei_finding(client, raw, asset_by_host)
        seen_hashes.add(kwargs["dedup_hash"])

        existing = db.query(Finding).filter_by(dedup_hash=kwargs["dedup_hash"]).first()
        if existing:
            # Same vuln, still present — just bump nothing, it's still open.
            continue

        db.add(Finding(**kwargs, created_at=now))
        new_count += 1

    # Fix verification: findings previously in_remediation that vanished this run
    resolved_count = 0
    in_remediation = db.query(Finding).filter_by(
        client_id=client.id, status=FindingStatus.in_remediation
    ).all()
    for f in in_remediation:
        if f.dedup_hash not in seen_hashes:
            f.status = FindingStatus.verified
            f.resolved_at = now
            resolved_count += 1

    db.commit()
    return new_count, resolved_count


def run_nuclei_default_logins_scan(targets: Iterable[str], timeout: int = 900) -> list[dict]:
    """
    Feature 2.2 — default-credential checks via nuclei's own `default-logins`
    template category, which actually attempts known default credential
    pairs against fingerprinted panels (Jenkins, Grafana, phpMyAdmin, and
    everything else nuclei's community templates cover) rather than just
    checking whether a login page is reachable. Reuses the same nuclei
    subprocess integration and authorized-scope model as the rest of the
    vuln scan -- only ever run against a client's own onboarded assets.
    Returns raw nuclei JSON results in the same shape as run_nuclei_scan,
    so callers feed them through the same parse_nuclei_finding path.
    """
    return run_nuclei_scan(targets, templates="default-logins/", timeout=timeout)
