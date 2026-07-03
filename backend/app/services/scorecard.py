"""
DSO-3 — Developer Security Scorecard.

Aggregates from the existing Finding table (matching pipeline/CI-sourced
findings by their title prefix -- "[Pipeline]"/"[CI Scan]", the same
title-prefix-as-source-tag convention used across devsecops.py/
triage.py/cspm.py) and DeveloperScorecardSnapshot, which stores one
rollup per client per day -- same shape idea as MetricSnapshot from the
first spec pass.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import Client, Finding, FindingStatus, DeveloperScorecardSnapshot

_PIPELINE_SOURCE_PREFIXES = ("[Pipeline]", "[CI Scan]", "[IaC]")


def compute_scorecard_metrics(db: Session, client_id: str) -> dict:
    all_findings = db.query(Finding).filter_by(client_id=client_id).all()
    pipeline_findings = [f for f in all_findings if f.title.startswith(_PIPELINE_SOURCE_PREFIXES)]

    total = len(pipeline_findings)
    blocked = sum(1 for f in pipeline_findings if f.title.startswith("[Pipeline]"))
    secrets_blocked = sum(1 for f in pipeline_findings if "secret" in (f.description or "").lower())

    resolved = [f for f in pipeline_findings if f.status in (FindingStatus.resolved, FindingStatus.verified) and f.resolved_at]
    mttr_hours = (
        round(sum((f.resolved_at - f.created_at).total_seconds() / 3600 for f in resolved) / len(resolved), 1)
        if resolved else None
    )

    open_count = sum(1 for f in pipeline_findings if f.status not in (FindingStatus.resolved, FindingStatus.verified))
    pipeline_health_score = max(0, 100 - min(100, open_count * 5))

    return {
        "pipeline_health_score": pipeline_health_score,
        "vulnerabilities_blocked": blocked,
        "secrets_blocked": secrets_blocked,
        "mttr_hours": mttr_hours,
        "total_pipeline_findings": total,
        "open_pipeline_findings": open_count,
    }


def snapshot_scorecard(db: Session, client: Client) -> DeveloperScorecardSnapshot:
    metrics = compute_scorecard_metrics(db, client.id)
    snapshot = DeveloperScorecardSnapshot(client_id=client.id, snapshot_date=datetime.utcnow(), metrics=metrics)
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def _claude_client():
    import anthropic
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate scorecard narrative.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def generate_scorecard_narrative(client_name: str, metrics: dict) -> str:
    ai = _claude_client()
    prompt = f"""Write a 150-200 word monthly developer security scorecard narrative for {client_name}.

Pipeline health score: {metrics['pipeline_health_score']}/100
Vulnerabilities blocked by CI gates this period: {metrics['vulnerabilities_blocked']}
Secrets blocked: {metrics['secrets_blocked']}
Mean time to fix: {metrics['mttr_hours']} hours (null means not enough resolved findings yet to compute)
Open pipeline findings: {metrics['open_pipeline_findings']}

Ground this strictly in the numbers above -- do not invent trends or comparisons not supported by this data. Cover: overall trend, the single most important thing to improve, and one encouraging or urgent closing note. No jargon overload, no greeting/sign-off."""

    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=400, messages=[{"role": "user", "content": prompt}])
    return "".join(block.text for block in response.content if block.type == "text").strip()


def export_scorecard_pdf(client_name: str, metrics: dict, narrative: str, output_path: str) -> str:
    """Lazy weasyprint import, matching ai_reports.py/compliance.py's export pattern."""
    import html
    from weasyprint import HTML

    html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
        body {{ font-family: Arial, sans-serif; font-size: 10pt; color: #1a1a2e; }}
        h1 {{ font-size: 20pt; }}
        .summary-grid {{ display: flex; gap: 12pt; margin: 12pt 0; }}
        .summary-cell {{ flex: 1; text-align: center; padding: 10pt; background: #f4f4f8; border-radius: 6pt; }}
        .summary-cell .num {{ font-size: 20pt; font-weight: bold; display: block; }}
    </style></head><body>
        <h1>{html.escape(client_name)} — Developer Security Scorecard</h1>
        <p>Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}. Confidential.</p>
        <div class="summary-grid">
            <div class="summary-cell"><span class="num">{metrics['pipeline_health_score']}</span>Pipeline Health</div>
            <div class="summary-cell"><span class="num">{metrics['vulnerabilities_blocked']}</span>Vulns Blocked</div>
            <div class="summary-cell"><span class="num">{metrics['secrets_blocked']}</span>Secrets Blocked</div>
            <div class="summary-cell"><span class="num">{metrics['mttr_hours'] if metrics['mttr_hours'] is not None else '—'}</span>MTTR (hrs)</div>
        </div>
        <h2>Narrative</h2>
        <p>{html.escape(narrative)}</p>
    </body></html>"""
    HTML(string=html_content).write_pdf(output_path)
    return output_path
