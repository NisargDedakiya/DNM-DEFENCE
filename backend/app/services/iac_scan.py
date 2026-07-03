"""
DSO-4 — IaC Security Scanner.

checkov (pip package) is the primary Terraform/CloudFormation/
Kubernetes/Helm/Compose scanner, invoked via its CLI entrypoint over
subprocess -- more version-stable across checkov releases than reaching
into its internal Python API classes, and consistent with this
codebase's dominant subprocess-with-graceful-degrade pattern (recon.py,
web3_scan.py's semgrep call). kube-score/hadolint/kubesec are OPTIONAL
subprocess enrichment, degrading the same way.

GitHub PR-comment posting reuses DSO-1's authenticated PyGithub client
(devsecops._github_client) rather than duplicating auth handling.
"""
import hashlib
import json
import logging
import subprocess
from datetime import datetime, timedelta

from app.core.config import settings
from app.models.models import Client, Finding, Severity, FindingStatus

logger = logging.getLogger(__name__)

_CHECKOV_SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_checkov(directory: str, timeout: int = 300) -> list[dict]:
    """Runs the `checkov` CLI against a directory of IaC files, requesting JSON output. Handles both single-report and multi-framework list output shapes."""
    try:
        proc = subprocess.run(
            ["checkov", "-d", directory, "-o", "json", "--quiet", "--compact"],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.warning("checkov not found on PATH — skipping IaC scan")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"checkov timed out scanning {directory}")
        return []

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []

    reports = data if isinstance(data, list) else [data]

    findings = []
    for report in reports:
        for check in (report.get("results", {}) or {}).get("failed_checks") or []:
            findings.append({
                "tool": "checkov", "check_id": check.get("check_id"),
                "severity": _CHECKOV_SEVERITY_MAP.get((check.get("severity") or "").upper(), "medium"),
                "resource": check.get("resource"), "description": check.get("check_name"),
                "file": check.get("file_path"),
                "line": (check.get("file_line_range") or [None])[0],
            })
    return findings


def run_optional_enrichment(binary: str, args: list[str], timeout: int = 120) -> str | None:
    """Runs an optional external tool (kube-score/hadolint/kubesec) if present on PATH. None means 'tool not installed', distinct from a real empty-output run."""
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        return proc.stdout[:4000]
    except FileNotFoundError:
        logger.info(f"`{binary}` not found on PATH — skipping optional enrichment")
        return None
    except subprocess.TimeoutExpired:
        logger.error(f"`{binary}` timed out")
        return None


def _claude_client():
    import anthropic
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate IaC fix suggestions.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def generate_fix_suggestion(finding: dict) -> str:
    ai = _claude_client()
    prompt = f"""You are a DevSecOps engineer. Suggest a concrete fix (a corrected IaC snippet or exact config change) for this finding:

Tool: {finding.get('tool')}
Check: {finding.get('check_id')} — {finding.get('description')}
Resource: {finding.get('resource')}
File: {finding.get('file')}

Give a 2-4 sentence fix, including a corrected snippet if applicable. No preamble."""
    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=300, messages=[{"role": "user", "content": prompt}])
    return "".join(block.text for block in response.content if block.type == "text").strip()


def _dedup_hash(client_id: str, check_id, file, resource) -> str:
    return hashlib.sha256(f"{client_id}:iac:{check_id}:{file}:{resource}".encode()).hexdigest()


def sync_iac_findings_to_db(db, client: Client, findings: list[dict]) -> int:
    """Syncs checkov (+ optional enrichment) findings into Finding, title-prefixed "[IaC]" -- same source-tagging convention as devsecops.py/triage.py."""
    now = datetime.utcnow()
    new_count = 0
    for f in findings:
        dedup = _dedup_hash(client.id, f.get("check_id"), f.get("file"), f.get("resource"))
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"[IaC] {f.get('check_id')}: {f.get('description') or 'misconfiguration'}",
            description=f"Resource: {f.get('resource')}\nFile: {f.get('file')}",
            severity=Severity(f.get("severity", "medium")), cvss_score=None, status=FindingStatus.new,
            evidence={"tool": f.get("tool"), "file": f.get("file"), "line": f.get("line"), "resource": f.get("resource")},
            remediation_steps=f.get("fix_suggestion") or "",
            dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=client.sla_hours_high),
        ))
        new_count += 1
    db.commit()
    return new_count


def post_pr_comment(repo_full_name: str, pr_number: int, findings: list[dict], token: str | None = None) -> dict:
    """Posts a summary comment on a PR listing IaC findings, reusing DSO-1's authenticated GitHub client."""
    from app.services.devsecops import _github_client

    gh = _github_client(token)
    repo = gh.get_repo(repo_full_name)
    pr = repo.get_pull(pr_number)

    if not findings:
        body = "**Track1 IaC Scan** — no findings. ✅"
    else:
        lines = ["**Track1 IaC Scan** found the following issues:", ""]
        for f in findings[:20]:
            lines.append(f"- **[{f['severity'].upper()}]** `{f.get('check_id')}` in `{f.get('file')}`: {f.get('description')}")
        body = "\n".join(lines)

    comment = pr.create_issue_comment(body)
    return {"comment_id": comment.id, "html_url": comment.html_url}
