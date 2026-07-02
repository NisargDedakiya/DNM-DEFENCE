"""
Module 1 — Asset Discovery & Continuous Monitoring.

Wraps external recon binaries (subfinder, httpx, naabu) as subprocesses,
parses their JSON output, and reconciles results against the Asset table.
These binaries are NOT bundled with this repo — install them separately:

    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

All scans here are READ-ONLY / passive-first by design. Anything active
(brute force, full port scans) must only run against domains the client
has explicitly authorized in their scope agreement — enforce that check
at the API layer before calling into this module, not here.
"""
import hashlib
import json
import socket
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Iterable

import httpx
from sqlalchemy.orm import Session

from app.models.models import Asset, AssetType, Port, Finding, Severity, FindingStatus

logger = logging.getLogger(__name__)

DANGEROUS_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}

# Feature 1.1 -- small built-in wordlist for active brute-force subdomain
# enumeration. Deliberately short: this is meant to catch common
# dev/staging/internal subdomains a passive source might miss, not to be
# an exhaustive brute-force -- keep the request volume against a client's
# domain reasonable.
BRUTEFORCE_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
    "dev", "staging", "test", "uat", "api", "admin", "portal", "app",
    "vpn", "remote", "internal", "intranet", "git", "gitlab", "jenkins",
    "jira", "confluence", "grafana", "kibana", "elastic", "db", "mysql",
    "postgres", "redis", "mongo", "backup", "old", "beta", "demo",
    "sandbox", "qa", "preprod", "prod", "monitor", "status", "docs",
]

# Feature 1.3 -- security headers every production web app should set.
# Missing entries become low/medium findings, not a full header audit.
SECURITY_HEADERS = {
    "content-security-policy": ("medium", "Missing Content-Security-Policy header — increases blast radius of any XSS."),
    "strict-transport-security": ("medium", "Missing Strict-Transport-Security (HSTS) header — allows protocol downgrade attacks."),
    "x-frame-options": ("low", "Missing X-Frame-Options header — page can be embedded in a clickjacking iframe."),
    "x-content-type-options": ("low", "Missing X-Content-Type-Options header — browser may MIME-sniff responses."),
}


def run_amass(root_domain: str, timeout: int = 600) -> list[str]:
    """
    Passive-mode Amass enumeration -- run alongside subfinder since the
    two tools' data sources overlap only partially; combining both catches
    more subdomains than either alone. Passive mode only (-passive flag)
    to stay non-intrusive by default.

    Install: go install -v github.com/owasp-amass/amass/v4/...@master
    """
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", root_domain, "-timeout", str(timeout // 60)],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.warning("amass binary not found on PATH — skipping (subfinder results still apply)")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"amass timed out for {root_domain}")
        return []

    hosts = {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
    return sorted(hosts)


def run_nmap_service_scan(hosts: list[str], timeout: int = 1800) -> dict[str, list[dict]]:
    """
    Feature 1.2 (real tool) — Nmap service/version detection. naabu (used
    elsewhere) is faster for raw port discovery; Nmap's -sV gives richer
    service/version fingerprinting worth running as a second pass on
    hosts naabu already flagged as having open ports, not as the primary
    port scanner (Nmap is much slower at scale).

    Install: apt-get install nmap (already common on security-tool base images)
    """
    if not hosts:
        return {}
    results: dict[str, list[dict]] = {}
    for host in hosts:
        try:
            proc = subprocess.run(
                ["nmap", "-sV", "-Pn", "--top-ports", "100", "-oX", "-", host],
                capture_output=True, text=True, timeout=timeout // max(len(hosts), 1),
            )
        except FileNotFoundError:
            logger.warning("nmap binary not found on PATH — skipping service/version detection")
            return {}
        except subprocess.TimeoutExpired:
            continue

        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(proc.stdout)
            services = []
            for port_el in root.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                services.append({
                    "port": int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "service_name": service_el.get("name") if service_el is not None else None,
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                })
            if services:
                results[host] = services
        except ET.ParseError:
            logger.error(f"Failed to parse nmap XML output for {host}")
    return results


def run_wappalyzer_fingerprint(url: str, timeout: int = 20) -> dict:
    """
    Feature 1.3 (real tool) — Wappalyzer technology fingerprinting.
    httpx's -tech-detect (used in run_httpx_probe) is a lighter built-in
    fingerprint; Wappalyzer's signature database is much larger and
    catches things httpx misses (analytics tools, JS frameworks, CMS
    plugins), worth the extra dependency for accurate tech-stack CVE
    matching later.

    Install: pip install python-Wappalyzer
    """
    try:
        from Wappalyzer import Wappalyzer, WebPage
    except ImportError:
        logger.warning("python-Wappalyzer not installed — falling back to httpx tech-detect only")
        return {}

    try:
        webpage = WebPage.new_from_url(url, timeout=timeout)
        wappalyzer = Wappalyzer.latest()
        return wappalyzer.analyze_with_versions_and_categories(webpage)
    except Exception as e:
        logger.error(f"Wappalyzer fingerprint failed for {url}: {e}")
        return {}


def run_sslyze_scan(hostname: str, port: int = 443, timeout: int = 30) -> dict | None:
    """
    Feature: real SSLyze integration. Goes well beyond the stdlib-ssl
    expiry check in dns_ssl_monitor.py — covers protocol/cipher weaknesses
    (SSLv3, weak ciphers, missing forward secrecy), not just cert expiry.

    Install: pip install sslyze
    """
    try:
        from sslyze import (
            Scanner, ServerScanRequest, ServerNetworkLocation,
            ScanCommand,
        )
    except ImportError:
        logger.warning("sslyze not installed — skipping deep TLS configuration scan")
        return None

    try:
        server_location = ServerNetworkLocation(hostname=hostname, port=port)
        scanner = Scanner()
        request = ServerScanRequest(
            server_location=server_location,
            scan_commands={ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES,
                           ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.CERTIFICATE_INFO},
        )
        scanner.queue_scans([request])

        issues = []
        for result in scanner.get_results():
            for cmd in (ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES):
                attr_result = result.scan_result.__dict__.get(cmd.value if hasattr(cmd, "value") else str(cmd))
                accepted = getattr(getattr(attr_result, "result", None), "accepted_cipher_suites", None) if attr_result else None
                if accepted:
                    issues.append(f"Server accepts deprecated/weak protocol: {cmd}")

        return {"hostname": hostname, "issues": issues}
    except Exception as e:
        logger.error(f"sslyze scan failed for {hostname}: {e}")
        return None


def run_subfinder(root_domain: str, timeout: int = 300) -> list[str]:
    """Passive subdomain enumeration. Returns a deduped list of hostnames."""
    try:
        result = subprocess.run(
            ["subfinder", "-d", root_domain, "-silent", "-oJ"],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.warning("subfinder binary not found on PATH — skipping passive enum")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"subfinder timed out for {root_domain}")
        return []

    hosts = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            hosts.add(obj.get("host", "").lower())
        except json.JSONDecodeError:
            # subfinder without -oJ falls back to plain text, one host per line
            hosts.add(line.lower())
    hosts.discard("")
    return sorted(hosts)


def run_httpx_probe(hosts: Iterable[str], timeout: int = 300) -> dict[str, dict]:
    """Probes hosts over HTTP(S) to confirm liveness and fingerprint tech stack."""
    if not hosts:
        return {}
    try:
        proc = subprocess.run(
            ["httpx", "-silent", "-json", "-tech-detect", "-status-code", "-title"],
            input="\n".join(hosts), capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.warning("httpx binary not found on PATH — skipping liveness probe")
        return {}
    except subprocess.TimeoutExpired:
        logger.error("httpx probe timed out")
        return {}

    results = {}
    for line in proc.stdout.splitlines():
        try:
            obj = json.loads(line)
            host = obj.get("host") or obj.get("input")
            results[host] = {
                "status_code": obj.get("status_code"),
                "title": obj.get("title"),
                "tech": obj.get("tech", []),
                "webserver": obj.get("webserver"),
            }
        except json.JSONDecodeError:
            continue
    return results


def run_naabu_portscan(hosts: Iterable[str], full_range: bool = False, timeout: int = 900) -> dict[str, list[dict]]:
    """Port scans given hosts. full_range scans all 65535 ports (slow); otherwise top 1000."""
    if not hosts:
        return {}
    cmd = ["naabu", "-silent", "-json"]
    cmd += ["-p", "-"] if full_range else ["-top-ports", "1000"]
    try:
        proc = subprocess.run(
            cmd, input="\n".join(hosts), capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.warning("naabu binary not found on PATH — skipping port scan")
        return {}
    except subprocess.TimeoutExpired:
        logger.error("naabu port scan timed out")
        return {}

    results: dict[str, list[dict]] = {}
    for line in proc.stdout.splitlines():
        try:
            obj = json.loads(line)
            host = obj.get("host") or obj.get("ip")
            port = obj.get("port")
            results.setdefault(host, []).append({
                "port": port,
                "is_dangerous": port in DANGEROUS_PORTS,
                "service_guess": DANGEROUS_PORTS.get(port),
            })
        except json.JSONDecodeError:
            continue
    return results


def run_subdomain_bruteforce(root_domain: str, timeout: int = 5) -> list[str]:
    """
    Feature 1.1 -- active brute-force subdomain enumeration, complementing
    the passive sources (subfinder/amass). Only ever run for onboarded
    clients under a signed scope agreement, same authorization posture as
    the rest of active scanning in this module (naabu full-range, etc.) --
    enforced by callers only running this from the client onboarding /
    scheduled-scan pipeline, never on an arbitrary domain.
    """
    found = []
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for word in BRUTEFORCE_WORDLIST:
            host = f"{word}.{root_domain}"
            try:
                socket.gethostbyname(host)
                found.append(host)
            except (socket.gaierror, socket.timeout):
                continue
    finally:
        socket.setdefaulttimeout(old_timeout)
    return found


def check_security_headers(hosts: list[str], timeout: int = 10) -> list[dict]:
    """
    Feature 1.3 -- HTTP security header analysis. Checks each live host for
    CSP/HSTS/X-Frame-Options/X-Content-Type-Options and reports what's
    missing. Best-effort: a host that's unreachable is skipped, not flagged
    (that's the SSL/liveness checks' job, not this one's).
    """
    results = []
    for host in hosts:
        url = host if host.startswith("http") else f"https://{host}"
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False)
        except httpx.HTTPError:
            continue
        headers_lower = {k.lower() for k in resp.headers.keys()}
        missing = [h for h in SECURITY_HEADERS if h not in headers_lower]
        if missing:
            results.append({"host": host, "missing": missing})
    return results


def check_cve_matches(tech_by_host: dict[str, list[str]], timeout: int = 10) -> list[dict]:
    """
    Feature 1.3 -- CVE matching for fingerprinted technology versions, via
    the free CIRCL CVE Search API (cve.circl.lu, no key required). Best-
    effort: CIRCL indexes by vendor/product slug, approximated here from
    the technology name (works for well-known single-word products like
    wordpress/nginx/apache; anything that doesn't resolve to a real
    vendor/product is silently skipped rather than guessed at).
    """
    hits = []
    checked = set()
    for host, techs in tech_by_host.items():
        for entry in techs:
            name, _, version = entry.partition(":")
            slug = name.strip().lower().replace(" ", "")
            if not slug or not version or slug in checked:
                continue
            checked.add(slug)
            try:
                resp = httpx.get(f"https://cve.circl.lu/api/search/{slug}/{slug}", timeout=timeout)
                if resp.status_code != 200:
                    continue
                data = resp.json()
            except (httpx.HTTPError, ValueError) as e:
                logger.info(f"CVE lookup skipped for {slug}: {e}")
                continue
            for cve in (data.get("data") or [])[:20]:
                summary = cve.get("summary", "")
                if version in summary:
                    hits.append({
                        "host": host, "technology": name.strip(), "version": version,
                        "cve_id": cve.get("id"), "summary": summary,
                        "cvss": cve.get("cvss") or 5.0,
                    })
    return hits


def sync_new_subdomain_findings_to_db(db: Session, client, new_hosts: list[str]) -> int:
    """Feature 1.1 -- turns the 'new subdomain appeared' signal into a real Finding, not just a log line."""
    now = datetime.utcnow()
    count = 0
    for host in new_hosts:
        dedup = hashlib.sha256(f"{client.id}:new_subdomain:{host}".encode()).hexdigest()
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"New subdomain discovered: {host}",
            description="This subdomain was not present in the previous scan. Verify it was authorized before assuming it's legitimate.",
            severity=Severity.info, cvss_score=0.0, status=FindingStatus.new,
            evidence={"host": host}, remediation_steps="Confirm this subdomain is expected; decommission or add to inventory tracking if not.",
            dedup_hash=dedup, created_at=now,
        ))
        count += 1
    db.commit()
    return count


def sync_port_findings_to_db(db: Session, client, new_port_details: list[dict]) -> int:
    """
    Feature 1.2 -- new-open-port and dangerous-service alerts as real
    Findings. new_port_details is a list of {"host", "port", "dangerous",
    "service"} for ports that are genuinely new this scan (not just
    re-seen), so re-scans don't spam duplicate findings.
    """
    now = datetime.utcnow()
    count = 0
    for detail in new_port_details:
        is_dangerous = detail["dangerous"]
        dedup = hashlib.sha256(f"{client.id}:port:{detail['host']}:{detail['port']}".encode()).hexdigest()
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        severity = Severity.high if is_dangerous else Severity.low
        title = (f"Dangerous service exposed: {detail.get('service') or 'unknown'} on port {detail['port']} — {detail['host']}"
                 if is_dangerous else f"New open port {detail['port']} on {detail['host']}")
        db.add(Finding(
            client_id=client.id, title=title,
            description=f"Port {detail['port']} is now open and reachable on {detail['host']}."
                        + (" This service type is commonly targeted and should not be internet-facing." if is_dangerous else ""),
            severity=severity, cvss_score=7.0 if is_dangerous else 2.0, status=FindingStatus.new,
            evidence=detail,
            remediation_steps="Restrict access via firewall/security group, or close the port if it's not intentionally exposed.",
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=client.sla_hours_high) if is_dangerous else None,
        ))
        count += 1
    db.commit()
    return count


def sync_header_findings_to_db(db: Session, client, header_results: list[dict]) -> int:
    """Feature 1.3 -- missing HTTP security header findings."""
    now = datetime.utcnow()
    count = 0
    for result in header_results:
        for header in result["missing"]:
            severity_label, description = SECURITY_HEADERS[header]
            dedup = hashlib.sha256(f"{client.id}:header:{result['host']}:{header}".encode()).hexdigest()
            if db.query(Finding).filter_by(dedup_hash=dedup).first():
                continue
            severity = Severity(severity_label)
            db.add(Finding(
                client_id=client.id, title=f"Missing {header} header — {result['host']}",
                description=description, severity=severity,
                cvss_score=4.0 if severity == Severity.medium else 2.0, status=FindingStatus.new,
                evidence={"host": result["host"], "header": header},
                remediation_steps=f"Set the `{header}` response header on {result['host']}.",
                dedup_hash=dedup, created_at=now,
            ))
            count += 1
    db.commit()
    return count


def sync_cve_findings_to_db(db: Session, client, cve_hits: list[dict]) -> int:
    """Feature 1.3 -- CVE findings for outdated fingerprinted software."""
    now = datetime.utcnow()
    count = 0
    for hit in cve_hits:
        dedup = hashlib.sha256(f"{client.id}:cve:{hit['host']}:{hit['cve_id']}".encode()).hexdigest()
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"{hit['cve_id']} — {hit['technology']} {hit['version']} on {hit['host']}",
            description=hit["summary"][:1000], severity=Severity.high, cvss_score=hit["cvss"],
            cve_id=hit["cve_id"], status=FindingStatus.new, evidence=hit,
            remediation_steps=f"Upgrade {hit['technology']} on {hit['host']} past version {hit['version']}.",
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=client.sla_hours_high),
        ))
        count += 1
    db.commit()
    return count


def sync_subdomains_to_db(db: Session, client_id: str, discovered_hosts: list[str]) -> tuple[int, list[str]]:
    """
    Reconciles freshly discovered hosts against the existing Asset table.
    Returns (count_of_new_assets, list_of_new_hostnames) so callers can
    fire "new subdomain" alerts (Feature 1.1) for only what's genuinely new.
    """
    existing = {
        a.value for a in db.query(Asset).filter_by(client_id=client_id, asset_type=AssetType.subdomain)
    }
    new_hosts = [h for h in discovered_hosts if h not in existing]

    now = datetime.utcnow()
    for host in discovered_hosts:
        asset = db.query(Asset).filter_by(client_id=client_id, asset_type=AssetType.subdomain, value=host).first()
        if asset:
            asset.last_seen = now
            asset.is_alive = True
        else:
            db.add(Asset(client_id=client_id, asset_type=AssetType.subdomain, value=host,
                          source="subfinder", first_seen=now, last_seen=now, is_alive=True))

    # Mark subdomains not seen in this run as potentially dead (Feature 1.1 dead-subdomain tracking)
    for asset in db.query(Asset).filter_by(client_id=client_id, asset_type=AssetType.subdomain):
        if asset.value not in discovered_hosts:
            asset.is_alive = False

    db.commit()
    return len(new_hosts), new_hosts


def sync_ports_to_db(db: Session, asset: Asset, ports: list[dict]) -> tuple[int, list[dict]]:
    """
    Upserts discovered ports for an asset. Returns (count_of_newly_opened,
    new_port_details) -- the latter feeds sync_port_findings_to_db so
    new-port/dangerous-service alerts fire only for genuinely new ports,
    not ones re-seen on every scan.
    """
    existing_ports = {p.port_number for p in asset.ports}
    new_count = 0
    new_details = []
    now = datetime.utcnow()
    for p in ports:
        if p["port"] not in existing_ports:
            new_count += 1
            db.add(Port(asset_id=asset.id, port_number=p["port"], service_name=p.get("service_guess"),
                        service_version=p.get("service_version"),
                        is_dangerous=p["is_dangerous"], first_seen=now, last_seen=now))
            new_details.append({"host": asset.value, "port": p["port"], "dangerous": p["is_dangerous"], "service": p.get("service_guess")})
        else:
            existing = next(x for x in asset.ports if x.port_number == p["port"])
            existing.last_seen = now
            if p.get("service_version"):
                existing.service_version = p["service_version"]
                existing.service_name = p.get("service_guess") or existing.service_name
    db.commit()
    return new_count, new_details
