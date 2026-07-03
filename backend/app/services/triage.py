"""
DSO-2 — Security Finding Triage Assistant.

Parses standard scanner output formats (SARIF, Trivy JSON, OWASP
Dependency-Check XML -- all plain JSON/XML, no new SDK dependency) into
a common shape, then uses Claude for false-positive classification,
context-aware severity recalibration, and fix-suggestion generation.
Jira ticket creation is a direct REST call via httpx, matching the
platform's existing lightweight-integration convention (no Jira SDK).
"""
import hashlib
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import httpx

from app.core.config import settings
from app.models.models import Client, Finding, Severity, FindingStatus

logger = logging.getLogger(__name__)

_SARIF_LEVEL_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_TRIVY_SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def parse_sarif(sarif_json: dict) -> list[dict]:
    findings = []
    for run in sarif_json.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        for result in run.get("results", []):
            level = result.get("level", "warning")
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            findings.append({
                "source_format": "sarif", "tool": tool_name, "check_id": result.get("ruleId"),
                "severity": _SARIF_LEVEL_MAP.get(level, "medium"),
                "message": (result.get("message") or {}).get("text", ""),
                "file": location.get("artifactLocation", {}).get("uri"),
                "line": location.get("region", {}).get("startLine"),
            })
    return findings


def parse_trivy_json(trivy_json: dict) -> list[dict]:
    findings = []
    for result in trivy_json.get("Results", []) or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "source_format": "trivy", "tool": "trivy", "check_id": vuln.get("VulnerabilityID"),
                "severity": _TRIVY_SEVERITY_MAP.get(vuln.get("Severity"), "medium"),
                "message": f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')}: {vuln.get('Title') or (vuln.get('Description') or '')[:200]}",
                "file": target, "line": None,
            })
    return findings


def _local_tag(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def parse_owasp_dependency_check_xml(xml_content: str) -> list[dict]:
    """Namespace-agnostic tree walk -- OWASP Dependency-Check's XML namespace URI has changed across versions, so this matches on local tag names instead of a hardcoded namespace."""
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        logger.error(f"Failed to parse OWASP Dependency-Check XML: {e}")
        return []

    findings = []
    for dep in root.iter():
        if _local_tag(dep.tag) != "dependency":
            continue
        file_name = "unknown"
        for child in dep:
            if _local_tag(child.tag) == "fileName":
                file_name = child.text or "unknown"
                break
        for vulns_el in dep:
            if _local_tag(vulns_el.tag) != "vulnerabilities":
                continue
            for v in vulns_el:
                if _local_tag(v.tag) != "vulnerability":
                    continue
                name, severity = None, "medium"
                for f in v:
                    if _local_tag(f.tag) == "name":
                        name = f.text
                    elif _local_tag(f.tag) == "severity":
                        severity = (f.text or "medium").lower()
                findings.append({
                    "source_format": "owasp_dependency_check", "tool": "owasp-dependency-check", "check_id": name,
                    "severity": severity if severity in _VALID_SEVERITIES else "medium",
                    "message": f"Vulnerable dependency: {file_name}" + (f" ({name})" if name else ""),
                    "file": file_name, "line": None,
                })
    return findings


def _claude_client():
    import anthropic
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot triage findings.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def triage_findings(findings: list[dict]) -> list[dict]:
    """Claude annotates each parsed finding with a false-positive verdict, a recalibrated severity, and a fix suggestion -- never drops a finding, only annotates."""
    if not findings:
        return findings

    ai = _claude_client()
    summaries = "\n".join(f"{i}. [{f['severity']}] {f['tool']}/{f.get('check_id')}: {f['message']}" for i, f in enumerate(findings))
    prompt = f"""You are triaging security scanner findings from a CI/CD pipeline.

Findings:
{summaries}

For each numbered finding, respond on its own line in exactly this format:
N: FALSE_POSITIVE|REAL | SEVERITY:<critical|high|medium|low|info> | FIX: <one-sentence concrete fix>
Do not skip any number."""

    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=1200, messages=[{"role": "user", "content": prompt}])
    text = "".join(block.text for block in response.content if block.type == "text").strip()

    parsed = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s*:\s*(FALSE_POSITIVE|REAL)\s*\|\s*SEVERITY:\s*(\w+)\s*\|\s*FIX:\s*(.*)", line)
        if m:
            parsed[int(m.group(1))] = {
                "verdict": m.group(2), "recalibrated_severity": m.group(3).lower(), "fix_suggestion": m.group(4).strip(),
            }

    for i, f in enumerate(findings):
        v = parsed.get(i, {"verdict": "REAL", "recalibrated_severity": f["severity"], "fix_suggestion": ""})
        f["ai_verdict"] = v["verdict"]
        f["recalibrated_severity"] = v["recalibrated_severity"] if v["recalibrated_severity"] in _VALID_SEVERITIES else f["severity"]
        f["fix_suggestion"] = v["fix_suggestion"]
    return findings


def create_jira_ticket(finding: dict, project_key: str = "SEC", timeout: int = 15) -> dict | None:
    """Direct REST call to Jira Cloud's issue-creation API. Key-gated -- degrades gracefully without JIRA_BASE_URL/JIRA_API_TOKEN/JIRA_EMAIL configured."""
    if not (settings.JIRA_BASE_URL and settings.JIRA_API_TOKEN and settings.JIRA_EMAIL):
        logger.info("Jira settings not fully configured — skipping ticket creation")
        return None

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[{finding['severity'].upper()}] {finding.get('tool')}: {finding.get('message', '')[:200]}",
            "description": finding.get("fix_suggestion") or finding.get("message", ""),
            "issuetype": {"name": "Bug"},
        }
    }
    try:
        resp = httpx.post(
            f"{settings.JIRA_BASE_URL}/rest/api/2/issue", json=payload, timeout=timeout,
            auth=(settings.JIRA_EMAIL, settings.JIRA_API_TOKEN),
        )
        if resp.status_code >= 300:
            logger.error(f"Jira ticket creation failed ({resp.status_code}): {resp.text}")
            return None
        return resp.json()
    except httpx.RequestError as e:
        logger.error(f"Jira request failed: {e}")
        return None


def _dedup_hash(client_id: str, check_id, file, message) -> str:
    return hashlib.sha256(f"{client_id}:ci_scan:{check_id}:{file}:{message}".encode()).hexdigest()


def sync_triage_findings_to_db(db, client: Client, findings: list[dict]) -> int:
    """Syncs triaged (non-false-positive) findings into Finding, title-prefixed "[CI Scan]" (same source-tagging convention as devsecops.py's "[Pipeline]" prefix)."""
    now = datetime.utcnow()
    new_count = 0
    for f in findings:
        if f.get("ai_verdict") == "FALSE_POSITIVE":
            continue
        severity_value = f.get("recalibrated_severity", f["severity"])
        dedup = _dedup_hash(client.id, f.get("check_id"), f.get("file"), f.get("message"))
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        db.add(Finding(
            client_id=client.id, title=f"[CI Scan] {f.get('tool')}: {f.get('check_id') or 'finding'}",
            description=f.get("message", ""),
            severity=Severity(severity_value), cvss_score=None, status=FindingStatus.new,
            evidence={"source_format": f.get("source_format"), "file": f.get("file"), "line": f.get("line")},
            remediation_steps=f.get("fix_suggestion") or "",
            dedup_hash=dedup, created_at=now, sla_deadline=now + timedelta(hours=client.sla_hours_high),
        ))
        new_count += 1
    db.commit()
    return new_count


def generate_weekly_triage_digest(client_name: str, findings_this_week: list[dict]) -> str:
    """Grounded strictly in this week's real triaged findings, same 'do not invent' discipline as ai_reports.py's weekly threat digest."""
    ai = _claude_client()
    if not findings_this_week:
        source_material = "No new CI/CD scanner findings this week — genuinely quiet."
    else:
        lines = [f"- [{f.get('recalibrated_severity', f['severity'])}] {f.get('tool')}/{f.get('check_id')}: {f.get('message', '')[:150]}"
                  for f in findings_this_week[:15]]
        source_material = "New CI/CD scanner findings this week:\n" + "\n".join(lines)

    prompt = f"""Write a short (150-200 word) weekly DevSecOps digest for {client_name}'s engineering team.

This is grounded strictly in real data from THIS WEEK's pipeline scans -- do not invent findings not in the data below.

{source_material}

Cover: what was found (in plain English), the single most important item to address, and one actionable takeaway. No jargon overload, no greeting/sign-off."""

    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=400, messages=[{"role": "user", "content": prompt}])
    return "".join(block.text for block in response.content if block.type == "text").strip()
