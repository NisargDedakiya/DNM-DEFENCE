"""
ZD-1 — Zero Day Research & Responsible Disclosure pipeline.

Tracking platform + optional local fuzz hook: this manages research
targets, findings, and the disclosure lifecycle (90-day Project-Zero-style
countdown), with real CVE/NVD lookups and real bug-bounty-platform/GitHub
Security Advisory submission integrations. FuzzingJob is an
analyst-updated tracking record for a campaign run OUTSIDE this platform
(AFL++/LibFuzzer/Boofuzz) -- this module does not orchestrate live fuzzing.
"""
import base64
import logging
from datetime import datetime, timedelta

import anthropic
import httpx

from app.core.config import settings
from app.models.models import ResearchFinding
from app.services.devsecops import _github_client

logger = logging.getLogger(__name__)

DISCLOSURE_DEADLINE_DAYS = 90  # Project Zero-style standard disclosure window

_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MITRE_CVE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"


def _claude_client() -> anthropic.Anthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate AI advisory content.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def check_cve_exists(cve_id: str, timeout: int = 15) -> bool:
    """Lightweight existence/state check against MITRE's own public CVE Services API -- free, keyless."""
    try:
        resp = httpx.get(_MITRE_CVE_URL.format(cve_id=cve_id), timeout=timeout)
        return resp.status_code == 200
    except httpx.HTTPError as e:
        logger.info(f"MITRE CVE existence check failed for {cve_id}: {e}")
        return False


def lookup_cve(cve_id: str, timeout: int = 15) -> dict | None:
    """
    Full CVE detail (description, CVSS score/vector, publish date) via the
    NVD API v2. Free and keyless for basic lookups; NVD_API_KEY (if set)
    only lifts the strict unauthenticated rate limit, it doesn't change
    the response shape.
    """
    headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
    try:
        resp = httpx.get(_NVD_CVE_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.info(f"NVD lookup failed for {cve_id}: {e}")
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0]["cve"]

    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss_score, cvss_vector = None, None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss_data = metrics[key][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            break

    return {
        "cve_id": cve.get("id"),
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }


def days_until_disclosure_deadline(vendor_notified: datetime | None,
                                    deadline_days: int = DISCLOSURE_DEADLINE_DAYS) -> int | None:
    """Standard 90-day disclosure countdown from the vendor-notified date. None if not yet notified."""
    if not vendor_notified:
        return None
    deadline = vendor_notified + timedelta(days=deadline_days)
    return (deadline - datetime.utcnow()).days


def submit_to_hackerone(finding: ResearchFinding, program_handle: str, api_identifier: str,
                         api_token: str | None = None, timeout: int = 20) -> dict | None:
    """Submits a report to HackerOne's real v1 REST API. Degrades to None if no token is configured."""
    token = api_token or settings.HACKERONE_API_TOKEN
    if not token:
        logger.info("HACKERONE_API_TOKEN not set — skipping HackerOne submission.")
        return None

    auth_header = base64.b64encode(f"{api_identifier}:{token}".encode()).decode()
    payload = {
        "data": {
            "type": "report",
            "attributes": {
                "title": finding.title,
                "vulnerability_information": finding.description or "",
                "impact": finding.vuln_class or "",
            },
            "relationships": {
                "program": {"data": {"type": "program", "attributes": {"handle": program_handle}}},
            },
        }
    }
    try:
        resp = httpx.post(
            "https://api.hackerone.com/v1/reports", json=payload, timeout=timeout,
            headers={"Authorization": f"Basic {auth_header}", "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as e:
        logger.warning(f"HackerOne submission failed for finding {finding.id}: {e}")
        return None


def submit_to_bugcrowd(finding: ResearchFinding, program_code: str, api_key: str | None = None,
                        timeout: int = 20) -> dict | None:
    """Submits a report to Bugcrowd's Crowdcontrol submissions API. Degrades to None if no key is configured."""
    key = api_key or settings.BUGCROWD_API_KEY
    if not key:
        logger.info("BUGCROWD_API_KEY not set — skipping Bugcrowd submission.")
        return None

    payload = {
        "submission": {
            "program_code": program_code,
            "title": finding.title,
            "description": finding.description or "",
            "vrt_id": finding.vuln_class or "",
        }
    }
    try:
        resp = httpx.post(
            "https://api.bugcrowd.com/submissions", json=payload, timeout=timeout,
            headers={"Authorization": f"Token {key}", "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as e:
        logger.warning(f"Bugcrowd submission failed for finding {finding.id}: {e}")
        return None


def publish_github_security_advisory(repo_full_name: str, finding: ResearchFinding, token: str | None = None) -> dict:
    """Publishes a repository security advisory via GitHub's real API, reusing devsecops.py's PyGithub client setup."""
    gh = _github_client(token)
    repo = gh.get_repo(repo_full_name)
    severity = (finding.severity.value if hasattr(finding.severity, "value") else finding.severity) or "medium"
    advisory = repo.create_repository_advisory(
        summary=finding.title,
        description=finding.description or "No further detail recorded.",
        severity_or_cvss_vector_string=severity,
        cve_id=finding.cve_id,
    )
    return {"id": advisory.ghsa_id, "html_url": advisory.html_url, "state": advisory.state}


def generate_disclosure_advisory(finding: ResearchFinding) -> str:
    """
    Claude-drafted vendor-disclosure advisory, grounded strictly in the
    recorded finding fields -- never invents CVSS scores, affected
    versions, or remediation steps beyond what's on file.
    """
    client_ai = _claude_client()
    deadline_days = days_until_disclosure_deadline(finding.vendor_notified)

    prompt = f"""Draft a formal responsible-disclosure security advisory, grounded strictly in the recorded details below — do not invent affected versions, CVSS scores, or remediation steps beyond what's given.

Title: {finding.title}
CVE ID: {finding.cve_id or 'not yet assigned'}
CVSS score: {finding.cvss_score if finding.cvss_score is not None else 'not scored'}
Vulnerability class: {finding.vuln_class or 'not specified'}
Description: {finding.description or 'not provided'}
Vendor notified: {finding.vendor_notified.isoformat() if finding.vendor_notified else 'not yet notified'}
Days until standard 90-day disclosure deadline: {deadline_days if deadline_days is not None else 'n/a'}

Write it in standard advisory format: Summary, Affected Component, Impact, Timeline, Recommendation. 300-500 words."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=1000,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()
