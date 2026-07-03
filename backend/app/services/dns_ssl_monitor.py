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
from datetime import datetime

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
        elif result["days_remaining"] <= 7:
            flagged.append({"hostname": host, "issue": "ssl_expiring_7d", "detail": f"Certificate expires in {result['days_remaining']} days — renew immediately."})
        elif result["days_remaining"] <= 14:
            flagged.append({"hostname": host, "issue": "ssl_expiring_14d", "detail": f"Certificate expires in {result['days_remaining']} days."})
        elif result["expiring_soon"]:
            flagged.append({"hostname": host, "issue": "ssl_expiring_30d", "detail": f"Certificate expires in {result['days_remaining']} days."})
    return flagged


def check_email_security(domain: str, timeout: int = 10) -> list[dict]:
    """
    Feature 2.3 — SPF/DKIM/DMARC validation. Checks the domain's SPF (in
    its TXT records) and DMARC (_dmarc TXT record) for presence and basic
    syntax. DKIM is checked at the common default selector only, since
    there's no way to discover a client's actual DKIM selector without
    them telling us -- a missing check here is a false negative, never a
    false positive.
    """
    issues = []
    txt_records = get_dns_records(domain, "TXT", timeout=timeout)
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]
    if not spf_records:
        issues.append({"issue": "spf_missing", "detail": f"No SPF record found for {domain} — mail claiming to be from this domain can't be authenticated by receivers."})
    elif len(spf_records) > 1:
        issues.append({"issue": "spf_multiple_records", "detail": f"{domain} has {len(spf_records)} SPF records — RFC 7208 requires exactly one; multiple records make SPF evaluation undefined."})
    elif not spf_records[0].rstrip('"').endswith(("-all", "~all")):
        issues.append({"issue": "spf_weak_policy", "detail": f"SPF record for {domain} doesn't end in -all or ~all — it doesn't actually restrict which servers can send mail as this domain."})

    dmarc_records = [r for r in get_dns_records(f"_dmarc.{domain}", "TXT", timeout=timeout) if "v=dmarc1" in r.lower()]
    if not dmarc_records:
        issues.append({"issue": "dmarc_missing", "detail": f"No DMARC record found for _dmarc.{domain} — spoofed mail claiming this domain has no enforcement or reporting policy."})
    elif "p=none" in dmarc_records[0].lower():
        issues.append({"issue": "dmarc_policy_none", "detail": f"DMARC policy for {domain} is p=none — spoofed mail is monitored but not rejected or quarantined."})

    dkim_records = get_dns_records(f"default._domainkey.{domain}", "TXT", timeout=timeout)
    if not dkim_records:
        issues.append({"issue": "dkim_not_found_default_selector", "detail": f"No DKIM record found at the common 'default' selector for {domain}. This is a best-effort check — the client may use a different selector."})

    return issues
