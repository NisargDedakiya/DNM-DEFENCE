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
import json
import subprocess
import logging
from datetime import datetime
from typing import Iterable

from sqlalchemy.orm import Session

from app.models.models import Asset, AssetType, Port

logger = logging.getLogger(__name__)

DANGEROUS_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}


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


def sync_ports_to_db(db: Session, asset: Asset, ports: list[dict]) -> int:
    """Upserts discovered ports for an asset. Returns count of newly-opened ports."""
    existing_ports = {p.port_number for p in asset.ports}
    new_count = 0
    now = datetime.utcnow()
    for p in ports:
        if p["port"] not in existing_ports:
            new_count += 1
            db.add(Port(asset_id=asset.id, port_number=p["port"], service_name=p.get("service_guess"),
                        service_version=p.get("service_version"),
                        is_dangerous=p["is_dangerous"], first_seen=now, last_seen=now))
        else:
            existing = next(x for x in asset.ports if x.port_number == p["port"])
            existing.last_seen = now
            if p.get("service_version"):
                existing.service_version = p["service_version"]
                existing.service_name = p.get("service_guess") or existing.service_name
    db.commit()
    return new_count
