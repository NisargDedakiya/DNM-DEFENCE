"""
SE-1 — OSINT Profiling Engine.

Ships everything that's safe and free: WHOIS + DNS history, email-pattern
guessing, Google dorking (Custom Search API, key-gated), GitHub OSINT,
job-listing tech-stack analysis, and a Claude-synthesized attacker-
perspective narrative.

Automated LinkedIn/social-media scraping is explicitly NOT built here —
it violates LinkedIn's ToS and risks account/IP bans, the same category
of decision as the Tor dark-web crawling flagged in threat_intel.py.
generate_osint_profile() always includes a note pointing to a paid data
provider (e.g. Proxycurl, PDL) or manual analyst input for that piece.
"""
import logging
import re
import subprocess
from datetime import datetime
from html import escape as _html_escape

import anthropic
import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import Client, OSINTProfile
from app.services.dns_ssl_monitor import get_dns_records

logger = logging.getLogger(__name__)

LINKEDIN_EXTENSION_NOTE = (
    "Automated LinkedIn/social-media scraping is out of scope for this "
    "platform (violates platform ToS and risks account/IP bans). Enrich "
    "this profile with employee/org-chart data via a paid provider "
    "(e.g. Proxycurl, PeopleDataLabs) or manual analyst research."
)

EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}{last}@{domain}",
    "{first}_{last}@{domain}",
    "{first}@{domain}",
    "{f}.{last}@{domain}",
]

DORK_TEMPLATES = [
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xls OR filetype:xlsx',
    'site:{domain} filetype:doc OR filetype:docx',
    'site:{domain} intitle:"index of"',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} ext:sql',
    'site:{domain} ext:log',
    'site:{domain} ext:env',
    'site:{domain} inurl:wp-content',
    'site:{domain} "internal use only"',
    'site:{domain} "confidential"',
    'site:pastebin.com "{domain}"',
    'site:trello.com "{domain}"',
    'site:docs.google.com "{domain}"',
]

TECH_KEYWORDS = [
    "AWS", "GCP", "Azure", "Kubernetes", "Docker", "React", "Node.js", "Python", "Django", "FastAPI",
    "PostgreSQL", "MySQL", "MongoDB", "Redis", "Terraform", "Jenkins", "GitLab", "Salesforce", "Okta",
    "Active Directory", "VPN", "Cisco", "SAP", "Java", "Spring", "PHP", "WordPress", ".NET", "Kafka",
    "Elasticsearch",
]


def get_whois(domain: str, timeout: int = 15) -> dict | None:
    """Uses the `whois` CLI (present on virtually every Linux base image), matching dns_ssl_monitor's `dig` subprocess pattern rather than adding a new dependency."""
    try:
        proc = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=timeout)
        raw = proc.stdout
    except FileNotFoundError:
        logger.warning("`whois` not found on PATH — skipping WHOIS lookup")
        return None
    except subprocess.TimeoutExpired:
        return None

    if not raw.strip():
        return None

    fields: dict[str, str] = {}
    name_servers: set[str] = set()
    for line in raw.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            value = value.strip()
            if not key or not value:
                continue
            if key.startswith("name_server"):
                # WHOIS output repeats this key once per name server -- a plain
                # dict would silently keep only the first (see key not in fields
                # below), so these are collected into a set instead.
                name_servers.add(value)
            elif key not in fields:
                fields[key] = value

    return {
        "registrar": fields.get("registrar"),
        "creation_date": fields.get("creation_date") or fields.get("created"),
        "expiration_date": fields.get("registry_expiry_date") or fields.get("expiration_date"),
        "name_servers": sorted(name_servers),
        "raw_excerpt": "\n".join(raw.splitlines()[:40]),
    }


def guess_email_patterns(domain: str, employee_names: list[str]) -> list[dict]:
    """Generates common corporate email-address guesses from a list of full names -- a lead list to verify, not confirmed addresses."""
    guesses = []
    for name in employee_names:
        parts = [p for p in name.strip().lower().split() if p]
        if len(parts) < 2:
            continue
        first, last = parts[0], parts[-1]
        for pattern in EMAIL_PATTERNS:
            guesses.append({
                "name": name,
                "guessed_email": pattern.format(first=first, last=last, f=first[0], domain=domain),
                "pattern": pattern,
            })
    return guesses


def run_google_dorks(domain: str, timeout: int = 15) -> list[dict]:
    """Feature: Google dorking via the Custom Search API. Key-gated — degrades gracefully like every other optional integration."""
    if not settings.GOOGLE_CSE_API_KEY or not settings.GOOGLE_CSE_CX:
        logger.info("GOOGLE_CSE_API_KEY/GOOGLE_CSE_CX not set — skipping Google dorking")
        return []

    results = []
    for template in DORK_TEMPLATES:
        query = template.format(domain=domain)
        try:
            resp = httpx.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": settings.GOOGLE_CSE_API_KEY, "cx": settings.GOOGLE_CSE_CX, "q": query, "num": 5},
                timeout=timeout,
            )
            if resp.status_code != 200:
                continue
            for item in resp.json().get("items", []):
                results.append({
                    "dork": query, "title": item.get("title"),
                    "link": item.get("link"), "snippet": item.get("snippet"),
                })
        except httpx.RequestError as e:
            logger.error(f"Google dork query failed ({query}): {e}")
    return results


def check_github_org_exposure(company_name: str, github_token: str | None = None, timeout: int = 15) -> list[dict]:
    """GitHub OSINT: finds public GitHub accounts self-identifying with this company -- a coarse signal for identifying employee accounts/repos worth a closer look, same pattern as threat_intel.check_github_secret_leaks."""
    token = github_token or settings.GITHUB_TOKEN
    if not token:
        logger.info("GITHUB_TOKEN not set — skipping GitHub OSINT search")
        return []

    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    try:
        resp = httpx.get(
            "https://api.github.com/search/users",
            params={"q": f'"{company_name}" in:company', "per_page": 10},
            headers=headers, timeout=timeout,
        )
        resp.raise_for_status()
        return [{"login": u.get("login"), "url": u.get("html_url")} for u in resp.json().get("items", [])]
    except httpx.HTTPStatusError as e:
        logger.error(f"GitHub OSINT search error: {e}")
        return []
    except httpx.RequestError as e:
        logger.error(f"GitHub OSINT request failed: {e}")
        return []


def analyze_job_listing(url: str, timeout: int = 15) -> dict | None:
    """Fetches a client-provided careers page and regex-scans it for tech-stack mentions -- a common source of internal infrastructure detail in job postings."""
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        logger.error(f"Job listing fetch failed for {url}: {e}")
        return None

    found = sorted({kw for kw in TECH_KEYWORDS if re.search(re.escape(kw), resp.text, re.IGNORECASE)})
    return {"url": url, "tech_mentions": found}


def _claude_client() -> anthropic.Anthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate OSINT narrative.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def synthesize_osint_narrative(client: Client, findings: dict) -> str:
    """Claude synthesizes the raw OSINT hits into an attacker-perspective narrative, grounded strictly in what was actually found."""
    ai = _claude_client()
    prompt = f"""You are a social engineering assessor summarizing OSINT reconnaissance findings for an authorized security engagement against {client.name}.

WHOIS: {findings.get('whois')}
DNS records: {findings.get('dns_records')}
Guessed email patterns (sample): {findings.get('email_patterns', [])[:10]}
Google dork hits: {len(findings.get('google_dorks', []))} result(s)
GitHub exposure hits: {len(findings.get('github_hits', []))} result(s)
Job listing tech-stack mentions: {findings.get('job_listing_tech', [])}

Write a 200-300 word attacker-perspective narrative: what an attacker doing external reconnaissance against this company would piece together from the above, which single piece of information is most useful for a phishing pretext, and the one OSINT-hardening recommendation that matters most. Do not invent facts that aren't present above -- if a section is empty, say so plainly rather than speculating. No preamble."""

    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=500, messages=[{"role": "user", "content": prompt}])
    return "".join(block.text for block in response.content if block.type == "text").strip()


def generate_osint_profile(db: Session, client: Client, employee_names: list[str] | None = None,
                            careers_page_url: str | None = None) -> OSINTProfile:
    """Orchestrates every check above into one OSINTProfile row."""
    domain = client.root_domain
    whois_data = get_whois(domain)
    dns_records = {rtype: get_dns_records(domain, rtype) for rtype in ("A", "MX", "NS", "TXT")}
    email_patterns = guess_email_patterns(domain, employee_names or [])
    google_dorks = run_google_dorks(domain)
    github_hits = check_github_org_exposure(client.name)
    job_listing = analyze_job_listing(careers_page_url) if careers_page_url else None

    findings = {
        "whois": whois_data,
        "dns_records": dns_records,
        "email_patterns": email_patterns,
        "google_dorks": google_dorks,
        "github_hits": github_hits,
        "job_listing_url": careers_page_url,
        "job_listing_tech": job_listing["tech_mentions"] if job_listing else [],
        "linkedin_note": LINKEDIN_EXTENSION_NOTE,
    }
    try:
        findings["narrative"] = synthesize_osint_narrative(client, findings)
    except RuntimeError as e:
        findings["narrative"] = f"AI synthesis unavailable: {e}"

    profile = OSINTProfile(client_id=client.id, generated_at=datetime.utcnow(), findings=findings)
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


def export_osint_profile_pdf(profile: OSINTProfile, client: Client, output_path: str) -> str:
    """Lazy weasyprint import, matching ai_reports.py's export_pdf pattern -- nothing else in this module needs it."""
    from weasyprint import HTML

    f = profile.findings or {}

    def _pre(value) -> str:
        return _html_escape(str(value))

    html = f"""<html><body style="font-family: sans-serif;">
    <h1>OSINT Profile &mdash; {_html_escape(client.name)}</h1>
    <p>Generated: {profile.generated_at}</p>
    <h2>Attacker-Perspective Narrative</h2><p>{_html_escape(f.get('narrative', ''))}</p>
    <h2>WHOIS</h2><pre>{_pre(f.get('whois'))}</pre>
    <h2>DNS Records</h2><pre>{_pre(f.get('dns_records'))}</pre>
    <h2>Guessed Email Patterns</h2><pre>{_pre(f.get('email_patterns'))}</pre>
    <h2>Google Dork Hits</h2><pre>{_pre(f.get('google_dorks'))}</pre>
    <h2>GitHub Exposure</h2><pre>{_pre(f.get('github_hits'))}</pre>
    <h2>Job Listing Tech Mentions</h2><pre>{_pre(f.get('job_listing_tech'))}</pre>
    <p><em>{_html_escape(f.get('linkedin_note', ''))}</em></p>
    </body></html>"""
    HTML(string=html).write_pdf(output_path)
    return output_path
