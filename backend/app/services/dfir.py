"""
DFIR-1 — Incident Response Case Manager.

Evidence hashes (MD5 + SHA256) are always computed server-side from the
uploaded bytes -- never trusted from the client, since evidentiary
integrity is the entire point of hashing. Chain-of-custody is an
append-only JSON list; nothing here ever rewrites or deletes a prior
custody entry.
"""
import hashlib
import logging
from datetime import datetime

import anthropic

from app.core.config import settings
from app.models.models import DfirCase, DfirEvidence, DfirIoc, DfirTimelineEntry

logger = logging.getLogger(__name__)


def _claude_client() -> anthropic.Anthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate AI report content.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def compute_file_hashes(data: bytes) -> dict:
    """Computes MD5 + SHA256 over raw evidence bytes -- the only trustworthy source for these hashes."""
    return {
        "md5_hash": hashlib.md5(data).hexdigest(),
        "sha256_hash": hashlib.sha256(data).hexdigest(),
        "file_size_bytes": len(data),
    }


def append_custody_entry(evidence: DfirEvidence, custodian: str, action: str) -> list[dict]:
    """Appends one entry to the evidence's chain-of-custody log. Never mutates or removes prior entries."""
    history = list(evidence.chain_of_custody or [])
    history.append({"timestamp": datetime.utcnow().isoformat(), "custodian": custodian, "action": action})
    return history


def generate_executive_report(case: DfirCase) -> str:
    """Claude-written, non-technical executive summary of the case -- grounded strictly in the case's own recorded fields."""
    client_ai = _claude_client()
    prompt = f"""Write a non-technical executive summary (250-350 words) of this incident response case, for a business audience (not security engineers). Ground it strictly in the facts below — do not invent details, dates, or outcomes not listed.

Case number: {case.case_number}
Incident type: {case.incident_type or 'not specified'}
Severity: {case.severity.value if hasattr(case.severity, 'value') else case.severity}
Status: {case.status.value if hasattr(case.status, 'value') else case.status}
Discovered: {case.discovered_at.isoformat() if case.discovered_at else 'not recorded'}
Contained: {case.contained_at.isoformat() if case.contained_at else 'not yet contained'}
Closed: {case.closed_at.isoformat() if case.closed_at else 'still open'}
Initial vector: {case.initial_vector or 'not yet determined'}
Affected systems: {', '.join(case.affected_systems) if case.affected_systems else 'none recorded'}
Data exfiltrated: {'yes' if case.data_exfiltrated else 'no evidence of exfiltration'}

Cover: what happened, business impact, current status, and next steps. Plain English, no jargon."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=800,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def generate_technical_report(case: DfirCase, evidence: list[DfirEvidence], iocs: list[DfirIoc],
                               timeline: list[DfirTimelineEntry]) -> str:
    """Claude-written technical report for a security-engineer audience -- grounded strictly in recorded evidence/IoCs/timeline."""
    client_ai = _claude_client()

    evidence_lines = [f"- {e.evidence_type or 'artifact'} from {e.source_host or 'unknown host'} "
                       f"(SHA256: {e.sha256_hash or 'not hashed'})" for e in evidence]
    ioc_lines = [f"- [{i.ioc_type}] {i.value} (confidence: {i.confidence})" for i in iocs]
    timeline_lines = [f"- [{t.timestamp}] {t.event_description} (host: {t.host or 'n/a'})"
                       for t in sorted(timeline, key=lambda x: x.timestamp)]

    prompt = f"""Write a technical incident response report (500-700 words) for a security engineering audience, grounded strictly in the recorded data below — do not invent evidence, IoCs, or timeline events not listed.

Case: {case.case_number} — {case.incident_type or 'unspecified incident'}
Initial vector: {case.initial_vector or 'not yet determined'}

Evidence collected:
{chr(10).join(evidence_lines) if evidence_lines else '  none recorded yet'}

Indicators of compromise:
{chr(10).join(ioc_lines) if ioc_lines else '  none recorded yet'}

Forensic timeline:
{chr(10).join(timeline_lines) if timeline_lines else '  none recorded yet'}

Structure: Summary, Root Cause Analysis, Timeline of Events, Indicators of Compromise, Recommendations."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def export_iocs_stix(iocs: list[DfirIoc]) -> dict:
    """Exports IoCs as a real STIX 2.1 bundle."""
    _STIX_PATTERN_FIELD = {"ip": "ipv4-addr:value", "domain": "domain-name:value", "url": "url:value",
                            "hash": "file:hashes.'SHA-256'", "email": "email-addr:value"}
    objects = []
    for ioc in iocs:
        field = _STIX_PATTERN_FIELD.get(ioc.ioc_type, "artifact:payload_bin")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc.id}",
            "created": (ioc.first_seen or datetime.utcnow()).isoformat() + "Z",
            "modified": (ioc.last_seen or ioc.first_seen or datetime.utcnow()).isoformat() + "Z",
            "pattern": f"[{field} = '{ioc.value}']",
            "pattern_type": "stix",
            "valid_from": (ioc.first_seen or datetime.utcnow()).isoformat() + "Z",
            "description": ioc.context or "",
            "confidence": {"low": 25, "medium": 50, "high": 85}.get(ioc.confidence, 50),
        })
    return {
        "type": "bundle",
        "id": f"bundle--{iocs[0].case_id if iocs else 'empty'}",
        "objects": objects,
    }


def export_iocs_sigma(iocs: list[DfirIoc]) -> str:
    """Exports IP/domain IoCs as a single Sigma detection rule (YAML string) -- network-indicator matching only."""
    import yaml

    network_iocs = [i for i in iocs if i.ioc_type in ("ip", "domain", "url")]
    rule = {
        "title": "DFIR case network indicators",
        "status": "experimental",
        "description": "Auto-generated from tracked DFIR case indicators of compromise.",
        "logsource": {"category": "network_connection"},
        "detection": {
            "selection": {"destination.ip|in" if any(i.ioc_type == "ip" for i in network_iocs) else "destination.domain|in":
                          [i.value for i in network_iocs]},
            "condition": "selection",
        },
        "level": "high",
    }
    return yaml.dump(rule, sort_keys=False)


def export_iocs_csv(iocs: list[DfirIoc]) -> str:
    """Exports IoCs as a CSV string."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ioc_type", "value", "confidence", "first_seen", "last_seen", "context", "attack_technique_id"])
    for i in iocs:
        writer.writerow([i.ioc_type, i.value, i.confidence,
                          i.first_seen.isoformat() if i.first_seen else "",
                          i.last_seen.isoformat() if i.last_seen else "",
                          i.context or "", i.attack_technique_id or ""])
    return buf.getvalue()
