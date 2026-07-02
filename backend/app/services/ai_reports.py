"""
Module 5 — AI Report Generation Engine.

Feature 5.1: monthly report generator (exec summary via Claude + technical
             findings table + PDF/Word export)
Feature 5.2: alert notification drafting for critical findings
Feature 5.3: weekly threat digest generator

The AI is only ever used for *writing* — summarizing and phrasing findings
that already exist in the database. It never decides severity, invents
findings, or is trusted with anything the human reviewer can't verify
against the underlying Finding rows before a report goes out.
"""
import logging
import os
import secrets
from datetime import datetime, timedelta

import anthropic
from docx import Document
from docx.shared import Pt, RGBColor
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session
from weasyprint import HTML

from app.core.config import settings
from app.models.models import Client, Finding, Severity, FindingStatus, Report, ReportType

logger = logging.getLogger(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates", "reports")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "generated_reports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

_jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))


def _claude_client() -> anthropic.Anthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate AI report content.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def _risk_score(counts: dict[str, int]) -> int:
    """
    Simple weighted risk score, 0 (best) to 100 (worst). Not meant to be
    a rigorous model — it's a directional indicator for the dashboard/report
    header, calibrated so a handful of open criticals dominates the score.
    """
    raw = counts["critical"] * 25 + counts["high"] * 10 + counts["medium"] * 3 + counts["low"] * 1
    return min(100, raw)


def _risk_band(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 35:
        return "high"
    if score >= 15:
        return "medium"
    return "good"


def gather_monthly_data(db: Session, client: Client, period_start: datetime, period_end: datetime) -> dict:
    """Feature 5.1 — pulls all findings/alerts/scans from the current month."""
    findings = (
        db.query(Finding)
        .filter(Finding.client_id == client.id, Finding.created_at >= period_start, Finding.created_at <= period_end)
        .order_by(Finding.cvss_score.desc())
        .all()
    )
    open_findings = db.query(Finding).filter(
        Finding.client_id == client.id, Finding.status.notin_([FindingStatus.resolved, FindingStatus.verified])
    ).all()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in open_findings:
        if f.severity.value in counts:
            counts[f.severity.value] += 1

    return {
        "findings_this_month": findings,
        "open_findings": open_findings,
        "counts": counts,
        "risk_score": _risk_score(counts),
    }


def generate_ai_remediation(finding_title: str, description: str, evidence: dict, tech_context: str = "") -> str:
    """
    Feature: AI-generated remediation, replacing the static per-issue
    template strings used elsewhere (vuln_scan.py, cspm.py). Those
    templates stay as the fallback default -- this function is meant to
    be called opportunistically to produce something more specific to
    the actual finding, not to replace the fallback entirely (if the AI
    call fails, the template still applies).
    """
    client_ai = _claude_client()
    prompt = f"""You are a security engineer writing remediation guidance for a specific finding. Be concrete and actionable -- name specific commands, config settings, or AWS/GCP/Azure console steps where relevant, not generic advice like "apply best practices."

Finding: {finding_title}
Description: {description or 'N/A'}
Technical evidence: {str(evidence)[:500]}
{f"Stack context: {tech_context}" if tech_context else ""}

Write 2-4 sentences of remediation steps a mid-level engineer could follow directly. No preamble, just the steps."""

    try:
        response = client_ai.messages.create(
            model=settings.ANTHROPIC_MODEL, max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text").strip()
    except Exception as e:
        logger.error(f"AI remediation generation failed, caller should fall back to static template: {e}")
        return ""


def generate_client_risk_analysis(client: Client, data: dict) -> str:
    """
    Feature: client-specific risk analysis narrative -- goes beyond the
    exec summary's plain-English tone to give a more analytical read on
    WHY the current posture looks the way it does and what pattern to
    watch, meant for a technical stakeholder (security-aware CTO,
    not a non-technical founder -- see generate_executive_summary for that).
    """
    client_ai = _claude_client()
    counts = data["counts"]
    top_findings = [(f.title, f.severity.value, f.cvss_score) for f in data["open_findings"][:8]]

    prompt = f"""Write a technical risk analysis (5-7 sentences) for {client.name}, a {client.industry or 'technology'} company.

Open findings: {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, {counts['low']} low
Top findings by severity: {top_findings}

Cover: (1) what pattern or theme connects the top findings, if any (e.g. "several findings trace back to unpatched dependencies" or "exposure is concentrated in cloud misconfigurations rather than application code"), (2) which single finding poses the most realistic business risk and why, (3) a forward-looking note on what to prioritize next cycle. Write for a technical stakeholder who wants substance, not reassurance. No preamble."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=450,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def generate_executive_summary(client: Client, data: dict) -> str:
    """
    Feature 5.1 — plain-English exec summary for a non-technical founder/CTO.
    The prompt gives Claude only aggregate counts and top finding titles —
    never raw evidence/exploit detail — since this text may be shared outside
    the security team.
    """
    client_ai = _claude_client()
    counts = data["counts"]
    top_titles = [f.title for f in data["open_findings"][:5]]

    prompt = f"""You are writing the executive summary for a monthly security report for a non-technical startup founder/CTO. Do not use jargon.

Client: {client.name} ({client.industry or "technology company"})
Currently open findings: {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, {counts['low']} low
Top open issues: {', '.join(top_titles) if top_titles else 'None currently open'}
New findings discovered this reporting period: {len(data['findings_this_month'])}

Write a 3-4 sentence executive summary covering: (1) overall security posture in plain English, (2) the single most important thing they should know or do this month, (3) a brief note of encouragement/context if the trend is positive, or urgency if it's not. Do not include a greeting or sign-off — just the summary paragraph itself."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL,
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def generate_compliance_summary(client: Client, data: dict) -> str:
    """Feature 5.1 — brief compliance status paragraph. Placeholder logic until Module 6 compliance checklists exist."""
    return (f"Formal SOC 2 / ISO 27001 / India DPDP Act control tracking is not yet configured for "
            f"{client.name}. Once compliance checklists are set up in the client portal, this section "
            f"will reflect real control implementation status.")


def render_report_html(client: Client, data: dict, executive_summary: str, period_label: str, risk_analysis: str = "") -> str:
    template = _jinja_env.get_template("monthly_report.html")
    return template.render(
        client_name=client.name,
        period_label=period_label,
        risk_score=data["risk_score"],
        risk_band=_risk_band(data["risk_score"]),
        executive_summary=executive_summary,
        risk_analysis=risk_analysis,
        counts=data["counts"],
        findings=[{
            "severity": f.severity.value, "title": f.title, "cvss_score": f.cvss_score,
            "status": f.status.value, "created_at": f.created_at.strftime("%Y-%m-%d"),
        } for f in data["open_findings"]],
        compliance_summary=generate_compliance_summary(client, data),
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )


def export_pdf(html_content: str, output_path: str) -> str:
    HTML(string=html_content).write_pdf(output_path)
    return output_path


def export_docx(client: Client, data: dict, executive_summary: str, period_label: str, output_path: str, risk_analysis: str = "") -> str:
    """Feature 5.1 — Word export for clients who need an editable report."""
    doc = Document()

    title = doc.add_heading(client.name, level=0)
    doc.add_paragraph(f"Monthly Security Report — {period_label}").italic = True

    doc.add_heading("Executive Summary", level=1)
    doc.add_paragraph(executive_summary)

    if risk_analysis:
        doc.add_heading("Technical Risk Analysis", level=1)
        doc.add_paragraph(risk_analysis)

    doc.add_heading("This Month at a Glance", level=1)
    counts = data["counts"]
    doc.add_paragraph(f"Critical: {counts['critical']}  |  High: {counts['high']}  |  "
                       f"Medium: {counts['medium']}  |  Low: {counts['low']}")

    doc.add_heading("Technical Findings", level=1)
    table = doc.add_table(rows=1, cols=4)
    table.style = "Light Grid Accent 1"
    hdr = table.rows[0].cells
    hdr[0].text, hdr[1].text, hdr[2].text, hdr[3].text = "Severity", "Finding", "CVSS", "Status"
    for f in data["open_findings"]:
        row = table.add_row().cells
        row[0].text = f.severity.value.upper()
        row[1].text = f.title
        row[2].text = str(f.cvss_score)
        row[3].text = f.status.value

    doc.save(output_path)
    return output_path


def generate_monthly_report(db: Session, client: Client) -> Report:
    """Orchestrates the full pipeline: gather data -> AI summary -> render -> export PDF+DOCX -> save Report row."""
    now = datetime.utcnow()
    period_start = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
    period_end = now.replace(day=1) - timedelta(seconds=1)
    period_label = period_start.strftime("%B %Y")

    data = gather_monthly_data(db, client, period_start, period_end)
    exec_summary = generate_executive_summary(client, data)
    risk_analysis = generate_client_risk_analysis(client, data)
    html = render_report_html(client, data, exec_summary, period_label, risk_analysis)

    safe_name = client.name.replace(" ", "_").replace("/", "-")
    pdf_path = os.path.join(OUTPUT_DIR, f"{safe_name}_{period_start.strftime('%Y-%m')}.pdf")
    docx_path = os.path.join(OUTPUT_DIR, f"{safe_name}_{period_start.strftime('%Y-%m')}.docx")
    export_pdf(html, pdf_path)
    export_docx(client, data, exec_summary, period_label, docx_path, risk_analysis)

    report = Report(
        client_id=client.id, report_type=ReportType.monthly_security,
        period_start=period_start, period_end=period_end,
        executive_summary=exec_summary, risk_analysis=risk_analysis, risk_score=data["risk_score"],
        pdf_path=pdf_path, docx_path=docx_path,
        share_token=secrets.token_urlsafe(24),  # Feature 6.5 — read-only share link
        created_at=now,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def draft_alert_notification(finding: Finding) -> str:
    """
    Feature 5.2 — drafts a client-facing alert for a critical/high finding.
    Human review before send is the default (see Celery task); auto-send
    is opt-in per client, not the default here.
    """
    client_ai = _claude_client()
    prompt = f"""Draft a short client alert notification (email-length, 4-6 sentences) about this security finding:

Title: {finding.title}
Severity: {finding.severity.value}
Description: {finding.description or 'N/A'}
Remediation: {finding.remediation_steps or 'N/A'}

Structure: (1) what was found, in plain English, (2) why it matters / potential impact, (3) what the client should do immediately, (4) what the security team will do next. No greeting or sign-off, just the body."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=350,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def generate_weekly_threat_digest(client: Client, recent_finding_titles: list[str]) -> str:
    """Feature 5.3 — 1-page plain-English weekly digest, tailored to industry/stack context."""
    client_ai = _claude_client()
    prompt = f"""Write a short (200-300 word) weekly security digest for a startup in the {client.industry or 'technology'} industry.

Recent findings on their systems this week: {', '.join(recent_finding_titles) if recent_finding_titles else 'None — quiet week'}

Cover: any new CVEs or threats relevant to a typical startup's stack this week, active threat campaigns worth knowing about in their industry, and one actionable takeaway. Plain English, no jargon, no greeting/sign-off — just the digest body."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()
