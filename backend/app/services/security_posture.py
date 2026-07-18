"""
vCISO layer — a plain-English security posture assessment for a startup or
small company that has no security team of its own.

Everything here is *interpretation* on top of data the platform already
collects: it reads the client's open findings (from every scan module) and
their SOC 2 compliance checklist and turns them into the three things a
founder actually needs instead of a wall of raw findings:

  1. an overall security grade (A-F) with a plain-English "what this means",
  2. a domain breakdown (which areas are weak), and
  3. a prioritized action plan -- the highest-impact fixes, in order, each
     with step-by-step guidance a non-security engineer can follow.

Plus SOC 2 readiness, because "can we pass a security review from a bigger
customer" is the question small companies get asked and can't answer.

No AI is required for any of the above -- the grade, domains, and action
plan are all computed from the data. An optional AI summary sits on top and
degrades gracefully (the scorecard still returns fully without it).
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import Client, Finding, FindingStatus, ScanRun, Severity
from app.services.compliance import get_compliance_summary

_OPEN_STATUSES = (FindingStatus.new, FindingStatus.acknowledged, FindingStatus.in_remediation, FindingStatus.disputed)

# Severity weights for the overall grade. Critical is deliberately heavy: one
# genuinely critical exposure should not read as a "B".
_SEVERITY_WEIGHT = {Severity.critical: 25, Severity.high: 12, Severity.medium: 4, Severity.low: 1, Severity.info: 0}
_SEVERITY_RANK = {Severity.critical: 4, Severity.high: 3, Severity.medium: 2, Severity.low: 1, Severity.info: 0}

# Startup-friendly domains. Each finding is bucketed by keyword-matching its
# title/description against these -- the buckets a founder recognises, not the
# scanner-tool names. Order matters: first match wins, so more specific
# buckets come before the catch-all.
_DOMAINS = [
    ("Exposed secrets & credentials", ["secret", "api key", "credential", "password", "token", "leaked", "breach", "dark web", "paste"]),
    ("Cloud security", ["s3", "bucket", "iam", "security group", "cloud", "kms", "public access", "storage account"]),
    ("Email security (phishing/spoofing)", ["spf", "dkim", "dmarc", "email", "mail"]),
    ("Encryption & certificates", ["ssl", "tls", "certificate", "cert ", "https", "expired"]),
    ("Vulnerable software", ["cve", "outdated", "vulnerab", "version", "patch", "end of life", "eol"]),
    ("Website & app hardening", ["header", "content-security-policy", "csp", "hsts", "x-frame", "clickjack", "cookie", "cors", "xss", "injection"]),
    ("Exposed services & attack surface", ["open port", "port ", "exposed service", "subdomain", "rdp", "ssh", "database", "redis", "mongo", "telnet"]),
]
_DOMAIN_FALLBACK = "Other security issues"

# Sensible default remediation when a finding has no stored steps -- keyed by
# domain so the guidance is at least directionally right for a non-expert.
_DOMAIN_FIX_HINTS = {
    "Exposed secrets & credentials": "Rotate the exposed secret immediately, remove it from any public location, and store secrets in a manager (AWS Secrets Manager, Doppler, 1Password) instead of code or config.",
    "Cloud security": "Lock down the resource: make storage private, restrict security-group rules to known IPs, and apply least-privilege IAM. Your cloud provider's Security Hub / Security Command Center flags most of these.",
    "Email security (phishing/spoofing)": "Add the missing DNS records: a strict SPF record ending in -all, a DKIM key from your email provider, and a DMARC record (start at p=none, then move to p=reject). Your email provider has copy-paste values.",
    "Encryption & certificates": "Renew or replace the certificate before it expires and enable auto-renewal (Let's Encrypt / your cloud's managed certs). Redirect all HTTP to HTTPS.",
    "Vulnerable software": "Update the affected software to a patched version. Turn on automated dependency updates (Dependabot / Renovate) so this doesn't recur.",
    "Website & app hardening": "Set the missing security headers on your web server or CDN (CSP, HSTS, X-Frame-Options, X-Content-Type-Options). Most hosts let you add these in a few lines of config.",
    "Exposed services & attack surface": "Close the port or put the service behind a firewall/VPN so it isn't reachable from the public internet. Only expose what genuinely needs to be public (usually just 80/443).",
    _DOMAIN_FALLBACK: "Review the finding details and remediation notes; if unsure, treat higher-severity items first.",
}

GRADE_MEANING = {
    "A": "Strong posture. Keep monitoring — no urgent exposures right now.",
    "B": "Good posture with a few gaps to close. Work the action plan below.",
    "C": "Fair posture. There are real gaps a determined attacker could use — prioritise the critical/high items this month.",
    "D": "Weak posture. Several serious exposures need attention soon.",
    "F": "At risk. One or more critical exposures should be fixed this week.",
}


def _classify_domain(finding: Finding) -> str:
    text = f"{finding.title} {finding.description or ''}".lower()
    for domain, keywords in _DOMAINS:
        if any(kw in text for kw in keywords):
            return domain
    return _DOMAIN_FALLBACK


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _why_it_matters(finding: Finding) -> str:
    """A one-line, non-jargon 'so what' for a founder, keyed off severity."""
    sev = finding.severity
    if sev == Severity.critical:
        return "An attacker could exploit this directly — treat it as urgent."
    if sev == Severity.high:
        return "This is a serious weakness that meaningfully raises your risk of a breach."
    if sev == Severity.medium:
        return "A moderate gap that makes an attack easier or a breach worse."
    return "A minor hygiene issue — low risk on its own, worth cleaning up."


def compute_posture(db: Session, client_id: str, max_actions: int = 8) -> dict:
    """The full startup security scorecard for one client. No AI required."""
    client = db.query(Client).get(client_id)
    if not client:
        raise ValueError(f"Client {client_id} not found")

    open_findings = (
        db.query(Finding)
        .filter(Finding.client_id == client_id, Finding.status.in_(_OPEN_STATUSES))
        .all()
    )
    scans_run = db.query(ScanRun).filter(ScanRun.client_id == client_id).count()

    # --- Overall grade ---
    penalty = min(100, sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in open_findings))
    score = 100 - penalty
    grade = _score_to_grade(score)

    counts = {s.value: 0 for s in Severity}
    for f in open_findings:
        counts[f.severity.value] += 1

    # --- Domain breakdown ---
    domain_findings: dict[str, list[Finding]] = {}
    for f in open_findings:
        domain_findings.setdefault(_classify_domain(f), []).append(f)

    domains = []
    for name, findings in domain_findings.items():
        dpenalty = min(100, sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings))
        worst = max(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0))
        domains.append({
            "domain": name,
            "score": 100 - dpenalty,
            "grade": _score_to_grade(100 - dpenalty),
            "open_findings": len(findings),
            "worst_severity": worst.severity.value,
        })
    domains.sort(key=lambda d: d["score"])  # weakest first

    # --- Prioritised action plan (guided fixes) ---
    ranked = sorted(
        open_findings,
        key=lambda f: (_SEVERITY_RANK.get(f.severity, 0), f.cvss_score or 0, f.created_at or datetime.min),
        reverse=True,
    )
    action_plan = []
    seen_titles = set()
    for f in ranked:
        if f.title in seen_titles:
            continue
        seen_titles.add(f.title)
        domain = _classify_domain(f)
        action_plan.append({
            "finding_id": f.id,
            "priority": len(action_plan) + 1,
            "title": f.title,
            "severity": f.severity.value,
            "domain": domain,
            "why_it_matters": _why_it_matters(f),
            "how_to_fix": (f.remediation_steps or "").strip() or _DOMAIN_FIX_HINTS.get(domain, _DOMAIN_FIX_HINTS[_DOMAIN_FALLBACK]),
        })
        if len(action_plan) >= max_actions:
            break

    # --- SOC 2 readiness (reuses the compliance checklist already seeded) ---
    compliance = get_compliance_summary(db, client_id)
    soc2 = compliance.get("soc2", {})
    soc2_readiness = {
        "percent_ready": soc2.get("percent_implemented", 0),
        "controls_total": soc2.get("total", 0),
        "controls_ready": soc2.get("implemented", 0),
        "controls_in_progress": soc2.get("in_progress", 0),
        "controls_missing": soc2.get("missing", 0),
    }

    return {
        "client_id": client_id,
        "client_name": client.name,
        "generated_at": datetime.utcnow().isoformat(),
        "grade": grade,
        "score": score,
        "grade_meaning": GRADE_MEANING[grade],
        "open_findings_total": len(open_findings),
        "open_by_severity": counts,
        "scans_run": scans_run,
        "assessment_ready": scans_run > 0,  # false = onboarded but no scan has completed yet
        "domains": domains,
        "action_plan": action_plan,
        "soc2_readiness": soc2_readiness,
    }


def generate_posture_summary(posture: dict) -> str | None:
    """
    Optional 2-3 sentence plain-English summary a non-technical founder can
    read. Grounded strictly in the computed scorecard -- never invents
    findings. Returns None (rather than raising) if AI isn't configured, so
    the scorecard endpoint always succeeds with or without a key.
    """
    if not settings.ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
        client_ai = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        weak = ", ".join(d["domain"] for d in posture["domains"][:3]) or "none"
        top = "; ".join(f"{a['title']}" for a in posture["action_plan"][:3]) or "none"
        prompt = f"""Write a 3-4 sentence security posture summary for the founder of {posture['client_name']}, a small company with no security team. Plain English, no jargon, encouraging but honest.

Overall grade: {posture['grade']} (score {posture['score']}/100).
Open issues: {posture['open_findings_total']} ({posture['open_by_severity']['critical']} critical, {posture['open_by_severity']['high']} high).
Weakest areas: {weak}.
Top things to fix: {top}.
SOC 2 readiness: {posture['soc2_readiness']['percent_ready']}%.

Ground it strictly in these numbers -- do not invent issues. Tell them where they stand and what to focus on first. No greeting or sign-off."""
        resp = client_ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=350, messages=[{"role": "user", "content": prompt}])
        return "".join(b.text for b in resp.content if b.type == "text").strip()
    except Exception:
        # AI is a nice-to-have here, not load-bearing -- never let it break
        # the scorecard. The numeric scorecard is the product.
        return None
