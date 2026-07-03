"""
Module 6.4 — Compliance Center backend.

Seeds each new client with a starter checklist for SOC 2, ISO 27001, and
India's DPDP Act. These are NOT exhaustive audit-ready control sets —
they're a representative starting checklist a founder can track progress
against and expand with their auditor. Treat as a starting point, not a
certified mapping.
"""
import html
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import Client, ComplianceControl, ComplianceFramework, ComplianceControlStatus

SOC2_STARTER_CONTROLS = [
    ("CC1.1", "Board and management demonstrate commitment to integrity and ethical values"),
    ("CC6.1", "Logical access security measures restrict access to authorized users"),
    ("CC6.6", "System boundaries are protected from unauthorized access (firewalls, network segmentation)"),
    ("CC7.2", "Security incidents are identified, evaluated, and responded to"),
    ("CC8.1", "Changes to infrastructure and software are authorized, tested, and approved"),
    ("A1.2", "Environmental protections, backup, and recovery infrastructure are in place"),
]

ISO27001_STARTER_CONTROLS = [
    ("A.5.1", "Policies for information security are defined and approved by management"),
    ("A.6.1", "Information security roles and responsibilities are defined"),
    ("A.8.1", "Inventory of information assets is maintained"),
    ("A.9.2", "User access provisioning is formally managed"),
    ("A.12.6", "Technical vulnerabilities are identified and remediated in a timely manner"),
    ("A.16.1", "Information security incidents are managed via a defined process"),
]

INDIA_DPDP_STARTER_CONTROLS = [
    ("DPDP-1", "Notice is given to data principals describing personal data processing"),
    ("DPDP-2", "Consent is obtained and is free, specific, informed, and unambiguous"),
    ("DPDP-3", "Data principal rights (access, correction, erasure) can be fulfilled on request"),
    ("DPDP-4", "Reasonable security safeguards are implemented to prevent personal data breaches"),
    ("DPDP-5", "Data breaches are reported to the Data Protection Board and affected principals"),
    ("DPDP-6", "Data retention limits are defined and enforced for personal data"),
]

# AI-2 — OWASP LLM Top 10, reusing the ComplianceControl shape instead of a
# parallel checklist model/table.
OWASP_LLM_STARTER_CONTROLS = [
    ("LLM01", "Prompt Injection — tested for direct/indirect injection resistance (see AI-1 Prompt Injection Testing Suite)"),
    ("LLM02", "Insecure Output Handling — LLM output is sanitized before use in downstream systems (rendering, DB, shell, etc.)"),
    ("LLM03", "Training Data Poisoning — data sources for any fine-tuning/RAG are vetted and access-controlled"),
    ("LLM04", "Model Denial of Service — rate limiting and input size limits are enforced on LLM-facing endpoints"),
    ("LLM05", "Supply Chain Vulnerabilities — model/library provenance and versions are tracked and monitored for CVEs"),
    ("LLM06", "Sensitive Information Disclosure — PII/secrets are filtered from prompts and completions"),
    ("LLM07", "Insecure Plugin Design — any tool/function-calling surface validates inputs and enforces least privilege"),
    ("LLM08", "Excessive Agency — autonomous actions are scoped, confirmed, and auditable, not unrestricted"),
    ("LLM09", "Overreliance — outputs are labeled as AI-generated and human review is required for high-stakes decisions"),
    ("LLM10", "Model Theft — access to model weights/embeddings/APIs is access-controlled and monitored"),
]

FRAMEWORK_SEEDS = {
    ComplianceFramework.soc2: SOC2_STARTER_CONTROLS,
    ComplianceFramework.iso27001: ISO27001_STARTER_CONTROLS,
    ComplianceFramework.india_dpdp: INDIA_DPDP_STARTER_CONTROLS,
    ComplianceFramework.owasp_llm: OWASP_LLM_STARTER_CONTROLS,
}


def seed_compliance_controls(db: Session, client: Client) -> int:
    """
    Called on client onboarding (Module 7 workflow). Idempotent per
    framework (not just per client) so it can be safely re-run to backfill
    a newly-added framework -- like owasp_llm -- for clients that were
    already onboarded before that framework existed.
    """
    now = datetime.utcnow()
    created = 0
    for framework, controls in FRAMEWORK_SEEDS.items():
        already_seeded = db.query(ComplianceControl).filter_by(client_id=client.id, framework=framework).count()
        if already_seeded > 0:
            continue
        for control_id, control_name in controls:
            db.add(ComplianceControl(
                client_id=client.id, framework=framework, control_id=control_id,
                control_name=control_name, status=ComplianceControlStatus.missing,
                updated_at=now,
            ))
            created += 1
    db.commit()
    return created


def get_compliance_summary(db: Session, client_id: str) -> dict:
    """
    Percentage-implemented rollup per framework. Single source of truth
    for both the portal's Compliance Center header (api/compliance.py)
    and the monthly report's compliance section (ai_reports.py) — they
    used to compute this independently and could drift.
    """
    controls = db.query(ComplianceControl).filter_by(client_id=client_id).all()
    summary = {}
    for c in controls:
        fw = c.framework.value
        summary.setdefault(fw, {"total": 0, "implemented": 0, "in_progress": 0, "missing": 0})
        summary[fw]["total"] += 1
        summary[fw][c.status.value] += 1
    for fw, s in summary.items():
        s["percent_implemented"] = round(100 * s["implemented"] / s["total"]) if s["total"] else 0
    return summary


FRAMEWORK_LABELS = {"soc2": "SOC 2", "iso27001": "ISO 27001", "india_dpdp": "India DPDP Act"}


def generate_compliance_report_pdf(db: Session, client: Client, output_path: str) -> str:
    """
    Feature 6.5 — compliance status report export for auditors/investors.
    Real per-control status, not just the percentage rollup -- an auditor
    needs to see which specific controls are missing, not just a number.
    """
    # Lazy import: weasyprint needs system libs not present in every
    # environment (matches the same pattern in ai_reports.py).
    from weasyprint import HTML

    controls = db.query(ComplianceControl).filter_by(client_id=client.id).order_by(
        ComplianceControl.framework, ComplianceControl.control_id
    ).all()
    summary = get_compliance_summary(db, client.id)

    rows_by_framework = {}
    for c in controls:
        rows_by_framework.setdefault(c.framework.value, []).append(c)

    sections = []
    for fw, rows in rows_by_framework.items():
        label = FRAMEWORK_LABELS.get(fw, fw)
        pct = summary.get(fw, {}).get("percent_implemented", 0)
        table_rows = "".join(
            f"<tr><td>{html.escape(c.control_id)}</td><td>{html.escape(c.control_name)}</td>"
            f"<td>{html.escape(c.status.value)}</td><td>{html.escape(c.evidence_notes or '')}</td></tr>"
            for c in rows
        )
        sections.append(f"""
        <h2>{html.escape(label)} — {pct}% implemented</h2>
        <table>
            <tr><th>Control</th><th>Description</th><th>Status</th><th>Evidence notes</th></tr>
            {table_rows}
        </table>
        """)

    html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
        body {{ font-family: Arial, sans-serif; font-size: 10pt; color: #1a1a2e; }}
        h1 {{ font-size: 20pt; }} h2 {{ font-size: 13pt; margin-top: 20pt; border-bottom: 1px solid #ccc; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 6pt; }}
        th {{ background: #16213e; color: white; text-align: left; padding: 5pt; font-size: 9pt; }}
        td {{ padding: 5pt; border-bottom: 1px solid #ddd; font-size: 9pt; }}
    </style></head><body>
        <h1>{html.escape(client.name)} — Compliance Status Report</h1>
        <p>Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}. Confidential.</p>
        {''.join(sections) if sections else '<p>No compliance controls configured yet.</p>'}
    </body></html>"""

    HTML(string=html_content).write_pdf(output_path)
    return output_path
