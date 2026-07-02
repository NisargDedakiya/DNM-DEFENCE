"""
DNS record monitoring + SSL certificate monitoring (audit-flagged gaps).
Both are lightweight, dependency-free checks (stdlib dns via subprocess
dig, stdlib ssl for cert inspection) so there's no new heavy SDK to
install for something this simple.
"""
import logging
import socket
import ssl
import subprocess
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

SSL_EXPIRY_WARNING_DAYS = 30


def get_dns_records(hostname: str, record_type: str = "A", timeout: int = 10) -> list[str]:
    """Uses `dig` (present on virtually every Linux base image) rather than adding a DNS library dependency."""
    try:
        proc = subprocess.run(
            ["dig", "+short", record_type, hostname], capture_output=True, text=True, timeout=timeout,
        )
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    except FileNotFoundError:
        logger.warning("`dig` not found on PATH — skipping DNS record check")
        return []
    except subprocess.TimeoutExpired:
        return []


def check_dns_drift(hostname: str, previous_records: dict[str, list[str]]) -> dict:
    """
    Compares current A/MX/NS/TXT records against a stored baseline.
    Returns {"changed": bool, "current": {...}, "diff": {...}}. A changed
    A or NS record on a client's root domain is a strong signal of DNS
    hijacking or an unauthorized change — worth a critical finding.
    """
    current = {rtype: get_dns_records(hostname, rtype) for rtype in ("A", "MX", "NS", "TXT")}
    diff = {}
    for rtype, values in current.items():
        prev = set(previous_records.get(rtype, []))
        if set(values) != prev:
            diff[rtype] = {"previous": sorted(prev), "current": sorted(values)}
    return {"changed": bool(diff), "current": current, "diff": diff}


def check_ssl_certificate(hostname: str, port: int = 443, timeout: int = 10) -> dict | None:
    """Connects and inspects the live cert: expiry, issuer, and days remaining."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        logger.error(f"SSL check failed for {hostname}: {e}")
        return None

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days_remaining = (not_after - datetime.utcnow()).days
    issuer = dict(x[0] for x in cert.get("issuer", []))

    return {
        "hostname": hostname, "expires_at": not_after.isoformat(),
        "days_remaining": days_remaining, "issuer": issuer.get("organizationName", "unknown"),
        "expiring_soon": days_remaining <= SSL_EXPIRY_WARNING_DAYS,
        "expired": days_remaining < 0,
    }


def check_ssl_fleet(hostnames: list[str]) -> list[dict]:
    """Runs the SSL check across every live host and returns only the ones worth flagging (expiring/expired/unreachable)."""
    flagged = []
    for host in hostnames:
        result = check_ssl_certificate(host)
        if result is None:
            flagged.append({"hostname": host, "issue": "ssl_unreachable", "detail": "Could not establish a TLS connection to inspect the certificate."})
        elif result["expired"]:
            flagged.append({"hostname": host, "issue": "ssl_expired", "detail": f"Certificate expired {abs(result['days_remaining'])} days ago."})
        elif result["expiring_soon"]:
            flagged.append({"hostname": host, "issue": "ssl_expiring_soon", "detail": f"Certificate expires in {result['days_remaining']} days."})
    return flagged
