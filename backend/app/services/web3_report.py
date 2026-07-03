"""WEB3-2 — Audit Report Generator (Web3 edition). Reuses ai_reports.py's lazy-weasyprint PDF export pattern."""
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates", "reports")
_jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _count_by_severity(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.get("severity") in counts:
            counts[f["severity"]] += 1
    return counts


def render_web3_audit_html(client_name: str, contract_name: str, network: str, findings: list[dict],
                            public_mode: bool = False) -> str:
    """public_mode redacts exploit-detail fields on critical/high findings -- suitable for sharing outside the immediate security team."""
    template = _jinja_env.get_template("web3_audit.html")
    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity"), 5))
    if public_mode:
        sorted_findings = [
            {**f, "description": "Details redacted in public summary mode.", "elements": []}
            if f.get("severity") in ("critical", "high") else f
            for f in sorted_findings
        ]
    return template.render(
        client_name=client_name, contract_name=contract_name, network=network,
        findings=sorted_findings, counts=_count_by_severity(findings), public_mode=public_mode,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )


def export_pdf(html_content: str, output_path: str) -> str:
    from weasyprint import HTML
    HTML(string=html_content).write_pdf(output_path)
    return output_path


def render_web3_audit_markdown(client_name: str, contract_name: str, network: str, findings: list[dict]) -> str:
    lines = [
        f"# {contract_name} — Smart Contract Security Audit", "",
        f"Client: {client_name}  ", f"Network: {network}  ",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", "",
    ]
    for f in sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity"), 5)):
        lines.append(f"## [{f.get('severity', 'info').upper()}] {f.get('check')} ({f.get('tool')})")
        lines.append("")
        lines.append(f.get("description") or "")
        if f.get("elements") and f["elements"][0].get("line"):
            lines.append("")
            lines.append(f"Location: line {f['elements'][0]['line']}")
        lines.append("")
    if not findings:
        lines.append("No findings from Slither/Semgrep or optional enrichment tools.")
    return "\n".join(lines)
