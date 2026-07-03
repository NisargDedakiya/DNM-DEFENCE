"""
AI-2 — AI Security Posture Dashboard.

CVE monitoring for AI/ML libraries reuses the free CIRCL CVE Search API
pattern from recon.check_cve_matches, applied to a client's declared AI
library stack instead of fingerprinted web tech. The OWASP LLM Top 10
checklist reuses the existing ComplianceControl model
(framework=owasp_llm) rather than a parallel checklist table -- see
compliance.py's OWASP_LLM_STARTER_CONTROLS.
"""
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


def check_ai_library_cves(library_versions: dict[str, str], timeout: int = 10) -> list[dict]:
    """library_versions example: {"tensorflow": "2.13.0", "langchain": "0.1.0"}."""
    hits = []
    for lib, version in library_versions.items():
        slug = lib.strip().lower().replace(" ", "")
        if not slug or not version:
            continue
        try:
            resp = httpx.get(f"https://cve.circl.lu/api/search/{slug}/{slug}", timeout=timeout)
            if resp.status_code != 200:
                continue
            data = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.info(f"CVE lookup skipped for {lib}: {e}")
            continue
        for cve in (data.get("data") or [])[:20]:
            summary = cve.get("summary", "")
            if version in summary:
                hits.append({
                    "library": lib, "version": version, "cve_id": cve.get("id"),
                    "summary": summary, "cvss": cve.get("cvss") or 5.0,
                })
    return hits


def _claude_client():
    import anthropic
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate AI security brief.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def generate_ai_security_brief(client_name: str, feature_count: int, cve_hits: list[dict], owasp_summary: dict) -> str:
    """Grounded strictly in real inventory/CVE/checklist data -- same "do not invent" discipline as ai_reports.py's weekly digest."""
    ai = _claude_client()
    cve_lines = [f"- {h['cve_id']}: {h['library']} {h['version']}" for h in cve_hits[:10]]
    prompt = f"""Write a 150-200 word monthly AI security brief for {client_name}.

AI/ML features in inventory: {feature_count}
CVE matches on their declared AI library stack this period:
{chr(10).join(cve_lines) if cve_lines else 'None found.'}
OWASP LLM Top 10 checklist status: {owasp_summary.get('percent_implemented', 0)}% implemented ({owasp_summary.get('implemented', 0)}/{owasp_summary.get('total', 0)} controls)

Ground this strictly in the data above -- do not invent CVEs or findings not listed. Cover: overall AI security posture, the single most important gap to close, and one encouraging or urgent closing note. No jargon overload, no greeting/sign-off."""

    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=400, messages=[{"role": "user", "content": prompt}])
    return "".join(block.text for block in response.content if block.type == "text").strip()
