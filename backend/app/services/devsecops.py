"""
DSO-1 — Pipeline Security Orchestrator.

GitHub Actions only for now: the platform already depends on PyGithub,
so this targets GitHub first. GitLab/Jenkins are documented extension
points (PipelineProvider has enum values for them, but no dispatch
function here) rather than three full CI-platform integrations in one
pass.

Deploys one of 5 pre-built gate-template workflows (rendered from
app/templates/pipeline_gates/) to a client's repo, then polls Actions
run results for that workflow into Finding rows -- title-prefixed
"[Pipeline]" (the same title-prefix-as-source-tag convention cspm.py
uses for cloud-provider tagging) rather than adding a new DB column.
"""
import hashlib
import logging
import os
from datetime import datetime, timedelta

from jinja2 import Environment, FileSystemLoader

from app.core.config import settings
from app.models.models import Client, Finding, Severity, FindingStatus

logger = logging.getLogger(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates", "pipeline_gates")
# Custom delimiters: these templates are GitHub Actions YAML, which uses
# `${{ ... }}` expressions pervasively -- plain Jinja2 `{{ }}` would
# collide with that syntax constantly. `[[ ]]` / `[% %]` never appear in
# YAML/Actions syntax, so no escaping games are needed in the templates.
_jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    variable_start_string="[[", variable_end_string="]]",
    block_start_string="[%", block_end_string="%]",
)

GATE_TEMPLATES = {
    "python_fastapi": "python_fastapi.yml.j2",
    "node_express": "node_express.yml.j2",
    "react": "react.yml.j2",
    "go": "go.yml.j2",
    "java_spring": "java_spring.yml.j2",
}

GATE_WORKFLOW_PATH = ".github/workflows/track1-security-gate.yml"


def render_gate_workflow(template_key: str, block_on_severity: str = "high") -> str:
    if template_key not in GATE_TEMPLATES:
        raise ValueError(f"Unknown gate template '{template_key}'. Choose from: {', '.join(GATE_TEMPLATES)}")
    template = _jinja_env.get_template(GATE_TEMPLATES[template_key])
    return template.render(block_on_severity=block_on_severity)


def _github_client(token: str | None = None):
    from github import Github, Auth
    tok = token or settings.GITHUB_TOKEN
    if not tok:
        raise RuntimeError("No GitHub token available (set GITHUB_TOKEN or pass one explicitly).")
    return Github(auth=Auth.Token(tok))


def deploy_gate_workflow(repo_full_name: str, template_key: str, block_on_severity: str = "high",
                         token: str | None = None, branch: str = "main") -> dict:
    """Commits (or updates) the rendered gate-template workflow YAML on the target repo's default branch."""
    gh = _github_client(token)
    repo = gh.get_repo(repo_full_name)
    content = render_gate_workflow(template_key, block_on_severity)

    try:
        existing = repo.get_contents(GATE_WORKFLOW_PATH, ref=branch)
        repo.update_file(GATE_WORKFLOW_PATH, f"Update Track1 security gate ({template_key})", content, existing.sha, branch=branch)
        action = "updated"
    except Exception:
        repo.create_file(GATE_WORKFLOW_PATH, f"Add Track1 security gate ({template_key})", content, branch=branch)
        action = "created"
    return {"action": action, "path": GATE_WORKFLOW_PATH}


def poll_pipeline_runs(repo_full_name: str, token: str | None = None, limit: int = 20) -> list[dict]:
    """Polls recent Actions run conclusions for the Track1 gate workflow specifically."""
    gh = _github_client(token)
    repo = gh.get_repo(repo_full_name)
    runs = []
    count = 0
    for run in repo.get_workflow_runs():
        if count >= limit:
            break
        if "track1-security-gate" not in (run.path or ""):
            continue
        runs.append({
            "run_id": run.id, "conclusion": run.conclusion, "status": run.status,
            "html_url": run.html_url,
            "created_at": run.created_at.isoformat() if getattr(run, "created_at", None) else None,
            "head_branch": run.head_branch, "head_sha": run.head_sha,
        })
        count += 1
    return runs


def _dedup_hash(client_id: str, repo_full_name: str, run_id) -> str:
    return hashlib.sha256(f"{client_id}:pipeline_gate:{repo_full_name}:{run_id}".encode()).hexdigest()


def sync_pipeline_findings_to_db(db, client: Client, repo_full_name: str, runs: list[dict]) -> int:
    """Creates a Finding for every failed gate run."""
    now = datetime.utcnow()
    new_count = 0
    for run in runs:
        if run.get("conclusion") != "failure":
            continue
        dedup = _dedup_hash(client.id, repo_full_name, run["run_id"])
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id,
            title=f"[Pipeline] Security gate failed — {repo_full_name}@{run.get('head_branch', '?')}",
            description=(f"The Track1 security gate workflow failed on commit {(run.get('head_sha') or '?')[:8]}. "
                         f"Review the run for details: {run.get('html_url')}"),
            severity=Severity.high, cvss_score=6.5, status=FindingStatus.new,
            evidence={"repo": repo_full_name, "run_id": run["run_id"], "html_url": run.get("html_url")},
            remediation_steps=("Review the failed pipeline run's logs/artifacts to identify which security check "
                                "blocked the build, then fix the underlying issue before merging."),
            dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=client.sla_hours_high),
        ))
        new_count += 1
    db.commit()
    return new_count
