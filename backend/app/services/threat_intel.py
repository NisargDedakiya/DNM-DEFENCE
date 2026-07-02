"""
Module 3 — Dark Web & Threat Intelligence Monitoring.

Feature 3.1: credential leak detection via Have I Been Pwned (HIBP) and,
             optionally, DeHashed.
Feature 3.2: GitHub secret scanning for accidentally-committed client
             API keys / tokens / domain references, plus best-effort
             paste-site monitoring (indexed Pastebin content via
             psbdmp.ws, free/no-key).
Feature 3.3: threat intel blocklist correlation (AlienVault OTX,
             Abuse.ch, Emerging Threats).

Tor-indexed dark-web content and ransomware-group blog monitoring still
require a paid feed (Flare, DarkOwl) or Tor-capable crawling
infrastructure that can't be built from free APIs — that piece is
stubbed with a clear extension point at the bottom of this file rather
than faked.
"""
import hashlib
import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import Client, Finding, Severity, FindingStatus

logger = logging.getLogger(__name__)

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


def check_hibp_breaches(domain: str, timeout: int = 15) -> list[dict]:
    """
    Feature 3.1 — queries HIBP's domain search API for breaches affecting
    the client's domain. Requires a paid HIBP API key (subscription-key
    header); without one this degrades gracefully and returns [].
    """
    if not settings.HIBP_API_KEY:
        logger.info("HIBP_API_KEY not set — skipping credential leak check")
        return []

    headers = {"hibp-api-key": settings.HIBP_API_KEY, "user-agent": "Track1-Platform"}
    try:
        resp = httpx.get(f"{HIBP_BASE}/breacheddomain/{domain}", headers=headers, timeout=timeout)
        if resp.status_code == 404:
            return []  # no breaches found — this is HIBP's "clean" response
        resp.raise_for_status()
        return resp.json() if isinstance(resp.json(), list) else []
    except httpx.HTTPStatusError as e:
        logger.error(f"HIBP API error for {domain}: {e}")
        return []
    except httpx.RequestError as e:
        logger.error(f"HIBP request failed for {domain}: {e}")
        return []


def check_github_secret_leaks(domain: str, github_token: str | None = None, timeout: int = 15) -> list[dict]:
    """
    Feature 3.2 — GitHub secret scanning. Searches public code for the
    client's domain alongside common secret-pattern keywords. This is a
    coarse signal (code search API, not full entropy scanning) — treat
    hits as leads to manually verify, not confirmed leaks.
    """
    token = github_token or settings.GITHUB_TOKEN
    if not token:
        logger.info("GITHUB_TOKEN not set — skipping GitHub secret scan")
        return []

    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    queries = [
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{domain}" password',
    ]
    results = []
    for q in queries:
        try:
            resp = httpx.get(
                "https://api.github.com/search/code",
                params={"q": q, "per_page": 10},
                headers=headers, timeout=timeout,
            )
            resp.raise_for_status()
            for item in resp.json().get("items", []):
                results.append({
                    "repo": item.get("repository", {}).get("full_name"),
                    "path": item.get("path"),
                    "url": item.get("html_url"),
                    "query_matched": q,
                })
        except httpx.HTTPStatusError as e:
            logger.error(f"GitHub search error: {e}")
        except httpx.RequestError as e:
            logger.error(f"GitHub request failed: {e}")
    return results


def check_threat_intel_blocklists(ip_addresses: list[str], timeout: int = 15) -> list[dict]:
    """
    Feature 3.3 — checks client IPs against AlienVault OTX's free
    reputation API. Flags any IP already known for malicious activity.
    """
    if not ip_addresses:
        return []
    hits = []
    for ip in ip_addresses:
        try:
            resp = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                timeout=timeout,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            if pulse_count > 0:
                hits.append({
                    "ip": ip,
                    "pulse_count": pulse_count,
                    "note": "IP appears in threat intelligence pulses — possible compromise or shared/malicious infrastructure.",
                })
        except httpx.RequestError as e:
            logger.error(f"OTX lookup failed for {ip}: {e}")
    return hits


def check_shodan(ip_addresses: list[str], timeout: int = 15) -> list[dict]:
    """
    Feature 3.3 — Shodan host lookups. Surfaces what an attacker doing
    passive recon would already see: open ports, banners, known
    vulnerabilities Shodan has tagged against the host.
    """
    if not settings.SHODAN_API_KEY or not ip_addresses:
        return []
    results = []
    for ip in ip_addresses:
        try:
            resp = httpx.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.SHODAN_API_KEY}, timeout=timeout,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            vulns = data.get("vulns", [])
            if vulns or data.get("ports"):
                results.append({
                    "ip": ip, "ports": data.get("ports", []), "vulns": list(vulns),
                    "org": data.get("org"), "os": data.get("os"),
                    "note": f"Shodan indexes this host with {len(data.get('ports', []))} open port(s)"
                            + (f" and {len(vulns)} known CVE(s) tagged against it." if vulns else "."),
                })
        except httpx.RequestError as e:
            logger.error(f"Shodan lookup failed for {ip}: {e}")
    return results


def check_censys(ip_addresses: list[str], timeout: int = 15) -> list[dict]:
    """Feature 3.3 — Censys host lookups. Similar surface to Shodan; the two indexes don't fully overlap, so both are worth running."""
    if not settings.CENSYS_API_ID or not settings.CENSYS_API_SECRET or not ip_addresses:
        return []
    results = []
    for ip in ip_addresses:
        try:
            resp = httpx.get(
                f"https://search.censys.io/api/v2/hosts/{ip}",
                auth=(settings.CENSYS_API_ID, settings.CENSYS_API_SECRET), timeout=timeout,
            )
            if resp.status_code != 200:
                continue
            data = resp.json().get("result", {})
            services = data.get("services", [])
            if services:
                results.append({
                    "ip": ip, "service_count": len(services),
                    "services": [s.get("service_name") for s in services],
                    "note": f"Censys indexes {len(services)} exposed service(s) on this host.",
                })
        except httpx.RequestError as e:
            logger.error(f"Censys lookup failed for {ip}: {e}")
    return results


def check_abusech(ip_addresses: list[str], timeout: int = 15) -> list[dict]:
    """
    Feature 3.3 — Abuse.ch ThreatFox IOC lookup (free API, no key
    required). Flags IPs that Abuse.ch's community-sourced feed has
    tagged as associated with malware C2 or other malicious activity.
    """
    if not ip_addresses:
        return []
    results = []
    for ip in ip_addresses:
        try:
            resp = httpx.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ip}, timeout=timeout,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                malware_families = {entry.get("malware") for entry in data["data"] if entry.get("malware")}
                results.append({
                    "ip": ip, "malware_families": sorted(f for f in malware_families if f),
                    "note": f"Abuse.ch ThreatFox has this IP tagged as IOC infrastructure"
                            + (f" for: {', '.join(sorted(malware_families))}." if malware_families else "."),
                })
        except httpx.RequestError as e:
            logger.error(f"Abuse.ch lookup failed for {ip}: {e}")
    return results


def check_paste_sites(domain: str, timeout: int = 15) -> list[dict]:
    """
    Feature 3.2 — paste-site monitoring, best-effort free-source version.
    Uses psbdmp.ws, a free paste-search index covering Pastebin (no key
    required). This is deliberately the free-tier substitute for the
    genuinely-paid/Tor-infra pieces of Module 3.2 (see the extension
    point at the bottom of this file) — it only covers indexed Pastebin
    content, not Ghostbin, ransomware blogs, or Tor-hidden services.
    """
    try:
        resp = httpx.get(f"https://psbdmp.ws/api/v3/search/{domain}", timeout=timeout)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (httpx.RequestError, ValueError) as e:
        logger.info(f"Paste-site search skipped for {domain}: {e}")
        return []

    hits = []
    for entry in (data.get("data") or [])[:20]:
        paste_id = entry.get("id")
        if not paste_id:
            continue
        hits.append({
            "paste_id": paste_id, "date": entry.get("time"),
            "url": f"https://pastebin.com/{paste_id}",
            "note": f"Client domain '{domain}' appears in an indexed Pastebin paste — review for leaked credentials, source code, or internal data.",
        })
    return hits


def check_dehashed(domain: str, timeout: int = 15) -> list[dict]:
    """
    Feature 3.1 — DeHashed breach/credential search, complementing HIBP
    with a different (paid, key-gated) data source. Degrades gracefully
    like every other optional integration when DEHASHED_API_KEY isn't set.
    """
    if not settings.DEHASHED_API_KEY:
        logger.info("DEHASHED_API_KEY not set — skipping DeHashed search")
        return []
    try:
        resp = httpx.get(
            "https://api.dehashed.com/search", params={"query": f"domain:{domain}"},
            auth=(settings.DEHASHED_API_KEY, "api_key"), timeout=timeout,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPStatusError, httpx.RequestError, ValueError) as e:
        logger.error(f"DeHashed search failed for {domain}: {e}")
        return []

    hits = []
    for entry in (data.get("entries") or [])[:50]:
        hits.append({
            "email": entry.get("email"), "database_name": entry.get("database_name"),
            "id": entry.get("id"),
            "note": f"Credential exposure found via DeHashed in database '{entry.get('database_name', 'unknown')}'.",
        })
    return hits


_ET_COMPROMISED_IPS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"


def check_emerging_threats(ip_addresses: list[str], timeout: int = 20) -> list[dict]:
    """
    Feature 3.3 — Emerging Threats (Proofpoint ET Open) compromised-ips
    blocklist. Free, no key required: fetches the plaintext IP list once
    per call and checks membership. Complements OTX/Abuse.ch since none
    of the three feeds fully overlap.
    """
    if not ip_addresses:
        return []
    try:
        resp = httpx.get(_ET_COMPROMISED_IPS_URL, timeout=timeout)
        resp.raise_for_status()
    except httpx.RequestError as e:
        logger.error(f"Emerging Threats blocklist fetch failed: {e}")
        return []

    blocked = {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}
    hits = []
    for ip in ip_addresses:
        if ip in blocked:
            hits.append({
                "ip": ip,
                "note": "IP appears on the Emerging Threats compromised-ips blocklist — a stronger signal than a generic reputation hit.",
            })
    return hits


def _dedup_hash(client_id: str, kind: str, identifier: str) -> str:
    return hashlib.sha256(f"{client_id}:{kind}:{identifier}".encode()).hexdigest()


def sync_intel_findings_to_db(db: Session, client: Client, breaches: list[dict],
                               github_hits: list[dict], blocklist_hits: list[dict],
                               shodan_hits: list[dict] | None = None, censys_hits: list[dict] | None = None,
                               abusech_hits: list[dict] | None = None, paste_hits: list[dict] | None = None,
                               dehashed_hits: list[dict] | None = None, et_hits: list[dict] | None = None) -> int:
    """Converts raw intel hits into Finding rows, deduped per-source."""
    now = datetime.utcnow()
    new_count = 0

    for b in breaches:
        name = b.get("Name") or b.get("Title") or "Unknown breach"
        dedup = _dedup_hash(client.id, "hibp_breach", name)
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"Credential breach affecting domain: {name}",
            description=b.get("Description", "Client domain email addresses were found in a known data breach."),
            severity=Severity.high, cvss_score=7.0, status=FindingStatus.new,
            evidence={"breach_name": name, "breach_date": b.get("BreachDate"), "data_classes": b.get("DataClasses", [])},
            remediation_steps="Force password resets for affected accounts and enable MFA where not already required.",
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=client.sla_hours_high),
        ))
        new_count += 1

    for g in github_hits:
        identifier = g["url"]
        dedup = _dedup_hash(client.id, "github_leak", identifier)
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"Possible secret exposure in public repo: {g['repo']}",
            description=f"A public GitHub file at {g['path']} matched a search for the client's domain alongside secret-like keywords ('{g['query_matched']}'). Manual verification required.",
            severity=Severity.high, cvss_score=7.5, status=FindingStatus.new,
            evidence=g, remediation_steps="Manually verify the file, revoke any real credentials found, and remove the secret from git history (not just the latest commit).",
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=client.sla_hours_high),
        ))
        new_count += 1

    for h in blocklist_hits:
        dedup = _dedup_hash(client.id, "threat_intel_ip", h["ip"])
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"IP {h['ip']} flagged in threat intelligence feeds",
            description=h["note"], severity=Severity.medium, cvss_score=5.5, status=FindingStatus.new,
            evidence=h, remediation_steps="Investigate whether this IP is compromised infrastructure, a shared host, or a false positive.",
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=168),
        ))
        new_count += 1

    for s in (shodan_hits or []):
        dedup = _dedup_hash(client.id, "shodan_exposure", s["ip"])
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        has_vulns = bool(s.get("vulns"))
        db.add(Finding(
            client_id=client.id, title=f"Shodan-indexed exposure — {s['ip']}",
            description=s["note"], severity=Severity.high if has_vulns else Severity.low,
            cvss_score=7.0 if has_vulns else 3.0, status=FindingStatus.new, evidence=s,
            remediation_steps="Review the exposed ports/services against what should actually be internet-facing; verify any tagged CVEs are patched.",
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=client.sla_hours_high if has_vulns else 168),
        ))
        new_count += 1

    for c in (censys_hits or []):
        dedup = _dedup_hash(client.id, "censys_exposure", c["ip"])
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"Censys-indexed exposure — {c['ip']}",
            description=c["note"], severity=Severity.low, cvss_score=3.0, status=FindingStatus.new,
            evidence=c, remediation_steps="Confirm every exposed service is intentional and necessary; close anything that isn't.",
            dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=168),
        ))
        new_count += 1

    for a in (abusech_hits or []):
        dedup = _dedup_hash(client.id, "abusech_ioc", a["ip"])
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"IP flagged as malware infrastructure (Abuse.ch) — {a['ip']}",
            description=a["note"], severity=Severity.critical, cvss_score=9.0, status=FindingStatus.new,
            evidence=a, remediation_steps="Treat as a likely compromise indicator — investigate this host immediately, this is a stronger signal than a generic blocklist hit.",
            dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=client.sla_hours_critical),
        ))
        new_count += 1

    for p in (paste_hits or []):
        dedup = _dedup_hash(client.id, "paste", p["paste_id"])
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"Domain mention in indexed paste — {p['paste_id']}",
            description=p["note"], severity=Severity.medium, cvss_score=5.0, status=FindingStatus.new,
            evidence=p, remediation_steps="Review the paste content; if it contains real credentials or internal data, rotate/revoke and consider a takedown request.",
            dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=168),
        ))
        new_count += 1

    for d in (dehashed_hits or []):
        identifier = d.get("id") or d.get("email") or str(d)
        dedup = _dedup_hash(client.id, "dehashed", identifier)
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"Credential exposure (DeHashed) — {d.get('database_name', 'unknown source')}",
            description=d["note"], severity=Severity.high, cvss_score=7.0, status=FindingStatus.new,
            evidence=d, remediation_steps="Force password resets for affected accounts and enable MFA where not already required.",
            dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=client.sla_hours_high),
        ))
        new_count += 1

    for e in (et_hits or []):
        dedup = _dedup_hash(client.id, "emerging_threats", e["ip"])
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"IP flagged on Emerging Threats compromised-ips list — {e['ip']}",
            description=e["note"], severity=Severity.critical, cvss_score=9.0, status=FindingStatus.new,
            evidence=e, remediation_steps="Treat as a likely compromise indicator — investigate this host immediately.",
            dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=client.sla_hours_critical),
        ))
        new_count += 1

    db.commit()
    return new_count


# --- Extension point ---
# check_paste_sites() above covers indexed Pastebin content (free,
# no key) as a best-effort substitute for the genuinely-paid pieces of
# Feature 3.2. Tor-indexed dark-web content and ransomware-group blog
# monitoring still need a paid feed (e.g. Flare, DarkOwl) or Tor-capable
# crawling infrastructure that can't be conjured from free APIs — wire a
# `check_dark_web_mentions(domain) -> list[dict]` function here following
# the same shape as the checks above once a feed is chosen, then add it
# to sync_intel_findings_to_db.
