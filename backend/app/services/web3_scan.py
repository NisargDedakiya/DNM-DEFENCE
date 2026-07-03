"""
WEB3-1 — Smart Contract Automated Scanner.

slither-analyzer (direct Python API) and semgrep (subprocess CLI against
a small bundled Solidity ruleset in app/rules/semgrep_solidity.yml) are
the two always-available primary engines -- both are pip-installable
with no extra system toolchain. mythril is wired as OPTIONAL subprocess
enrichment (needs a much heavier Z3/solc toolchain) and degrades
gracefully via the same try/except FileNotFoundError pattern used
elsewhere in this codebase (recon.py's amass/nmap calls) rather than
being a hard dependency.

echidna (property-based fuzzing) is NOT auto-invoked here: it requires
contract-specific Solidity invariant/property test functions that can't
be generically generated, so it stays a documented manual follow-up for
the analyst rather than a fake automated integration.
"""
import json
import logging
import os
import re
import subprocess

from app.core.config import settings

logger = logging.getLogger(__name__)

_SLITHER_SEVERITY_MAP = {"High": "critical", "Medium": "high", "Low": "medium", "Informational": "info", "Optimization": "info"}
_SEMGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_MYTHRIL_SEVERITY_MAP = {"High": "critical", "Medium": "high", "Low": "medium"}

_DEFAULT_SEMGREP_RULES = os.path.join(os.path.dirname(__file__), "..", "rules", "semgrep_solidity.yml")


def detect_solc_version(source: str) -> str | None:
    """Parses the contract's own pragma line -- this is a hint for the analyst, not an auto-install of the matching solc version."""
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    return match.group(1).strip() if match else None


def run_slither(source_path: str) -> list[dict]:
    try:
        from slither import Slither
    except ImportError:
        logger.warning("slither-analyzer not installed — skipping Slither analysis")
        return []

    try:
        sl = Slither(source_path)
        raw_results = sl.run_detectors()
    except Exception as e:
        logger.error(f"Slither failed to analyze {source_path}: {e}")
        return []

    findings = []
    for detector_results in raw_results or []:
        for result in detector_results or []:
            findings.append({
                "tool": "slither",
                "check": result.get("check"),
                "severity": _SLITHER_SEVERITY_MAP.get(result.get("impact"), "medium"),
                "description": result.get("description"),
                "elements": [{"line": e.get("source_mapping", {}).get("lines", [None])[0]} for e in result.get("elements", [])][:1],
            })
    return findings


def run_semgrep(source_path: str, rules_path: str | None = None, timeout: int = 60) -> list[dict]:
    rules_path = rules_path or _DEFAULT_SEMGREP_RULES
    try:
        proc = subprocess.run(
            ["semgrep", "--config", rules_path, "--json", "--quiet", source_path],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.warning("semgrep not found on PATH — skipping Semgrep scan")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"semgrep timed out scanning {source_path}")
        return []

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []

    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        findings.append({
            "tool": "semgrep",
            "check": result.get("check_id"),
            "severity": _SEMGREP_SEVERITY_MAP.get(extra.get("severity"), "medium"),
            "description": extra.get("message"),
            "elements": [{"line": result.get("start", {}).get("line")}],
        })
    return findings


def run_mythril(source_path: str, timeout: int = 300) -> list[dict]:
    """Optional enrichment -- mythril needs a heavier Z3/solc toolchain, not a hard dependency."""
    try:
        proc = subprocess.run(["myth", "analyze", source_path, "-o", "json"], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        logger.info("mythril (`myth`) not found on PATH — skipping optional enrichment")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"mythril timed out analyzing {source_path}")
        return []

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []

    findings = []
    for issue in data.get("issues", []):
        findings.append({
            "tool": "mythril",
            "check": issue.get("swc-id"),
            "severity": _MYTHRIL_SEVERITY_MAP.get(issue.get("severity"), "medium"),
            "description": issue.get("description") or issue.get("title"),
            "elements": [{"line": issue.get("lineno")}],
        })
    return findings


def _dedup_key(finding: dict) -> tuple:
    line = finding["elements"][0].get("line") if finding.get("elements") else None
    rule_family = (finding.get("check") or "").split("-")[0] or finding.get("tool")
    return (line, rule_family)


def dedup_findings(findings: list[dict]) -> list[dict]:
    """Dedupes across tools by (line, rule-family) so Slither/Semgrep/Mythril flagging the same real issue doesn't produce 3 findings."""
    seen = set()
    deduped = []
    for f in findings:
        key = _dedup_key(f)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def _claude_client():
    import anthropic
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot run AI false-positive filtering.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def filter_false_positives(contract_source: str, findings: list[dict]) -> list[dict]:
    """
    Claude reviews each raw tool finding against the actual contract
    context and annotates likely false positives -- it never silently
    deletes a finding, only tags ai_verdict/ai_reason so a human makes
    the final call.
    """
    if not findings:
        return findings

    ai = _claude_client()
    finding_summaries = "\n".join(f"{i}. [{f['tool']}/{f['check']}] {f['description']}" for i, f in enumerate(findings))
    prompt = f"""You are reviewing static-analysis findings against this Solidity contract for likely false positives.

Contract source (may be truncated):
{contract_source[:4000]}

Findings:
{finding_summaries}

For each numbered finding, respond on its own line as: "N: LIKELY_REAL" or "N: LIKELY_FALSE_POSITIVE - <one sentence reason>". Do not skip any number."""

    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=800, messages=[{"role": "user", "content": prompt}])
    text = "".join(block.text for block in response.content if block.type == "text").strip()

    verdicts = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s*:\s*(LIKELY_REAL|LIKELY_FALSE_POSITIVE)(?:\s*-\s*(.*))?", line)
        if m:
            verdicts[int(m.group(1))] = {"verdict": m.group(2), "reason": (m.group(3) or "").strip()}

    for i, f in enumerate(findings):
        v = verdicts.get(i, {"verdict": "LIKELY_REAL", "reason": ""})
        f["ai_verdict"] = v["verdict"]
        f["ai_reason"] = v["reason"]
    return findings


def run_contract_scan(source: str) -> dict:
    """Orchestrates Slither + Semgrep + optional Mythril against a Solidity source string, then dedupes and (if configured) AI-filters."""
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as tmp:
        tmp.write(source)
        tmp_path = tmp.name

    try:
        findings = run_slither(tmp_path) + run_semgrep(tmp_path) + run_mythril(tmp_path)
    finally:
        os.unlink(tmp_path)

    findings = dedup_findings(findings)
    try:
        findings = filter_false_positives(source, findings)
    except RuntimeError:
        logger.info("ANTHROPIC_API_KEY not set — findings returned unfiltered (the safe default)")

    return {"solc_version_hint": detect_solc_version(source), "findings": findings}
