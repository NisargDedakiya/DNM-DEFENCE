"""
RT-1 — Red Team Operations tracking/logging tool.

This is deliberately NOT a C2 framework. It does not run a server, deploy
implants, or execute attacks. A human operator runs real tooling (Cobalt
Strike, Havoc, Sliver, etc.) outside this platform and logs what happened
here afterwards — operation workspace, timeline, implant/infrastructure
trackers, ATT&CK tagging, and AI-written narrative/debrief reports. This
mirrors how real-world red team tracking tools (Ghostwriter, RedELK) work.
"""
import logging

import anthropic

from app.core.config import settings
from app.models.models import RedTeamOperation, RedTeamTimelineEntry
from app.services.attack_framework import generate_navigator_layer
from app.services.threat_intel import check_shodan

logger = logging.getLogger(__name__)


def _claude_client() -> anthropic.Anthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate AI narrative content.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def generate_attck_heatmap(timeline_entries: list[RedTeamTimelineEntry]) -> dict:
    """Builds a real ATT&CK Navigator layer from this operation's logged, technique-tagged timeline entries."""
    counts: dict[str, int] = {}
    for entry in timeline_entries:
        if entry.attack_technique_id:
            counts[entry.attack_technique_id] = counts.get(entry.attack_technique_id, 0) + 1
    return generate_navigator_layer(counts, name="Red Team Operation — ATT&CK Coverage",
                                     description="Techniques logged during this engagement's timeline.")


def check_c2_infra_exposure(ip_addresses: list[str]) -> list[dict]:
    """
    Verifies the team's own C2/redirector infrastructure isn't already
    fingerprinted by Shodan before (or during) an engagement — reuses the
    same Shodan lookup Module 3 uses for target recon, pointed at the
    operator's own infra instead.
    """
    if not ip_addresses:
        return []
    return check_shodan(ip_addresses)


def generate_attack_narrative(operation: RedTeamOperation, timeline_entries: list[RedTeamTimelineEntry]) -> str:
    """
    Claude-written narrative summarizing the operation, grounded strictly
    in the real logged timeline — never invents actions, hosts, or
    outcomes beyond what the operator actually recorded.
    """
    client_ai = _claude_client()

    if not timeline_entries:
        source_material = "No timeline entries have been logged for this operation yet."
    else:
        lines = []
        for e in sorted(timeline_entries, key=lambda x: x.timestamp):
            detected = e.detected.value if hasattr(e.detected, "value") else e.detected
            lines.append(
                f"- [{e.timestamp}] ({e.phase.value if hasattr(e.phase, 'value') else e.phase}) "
                f"{e.action} | host={e.host or 'n/a'} user={e.user_context or 'n/a'} "
                f"tool={e.tool_used or 'n/a'} outcome={e.outcome or 'n/a'} detected={detected}"
                + (f" technique={e.attack_technique_id}" if e.attack_technique_id else "")
            )
        source_material = "\n".join(lines)

    prompt = f"""Write a clear attack narrative for this red team operation, strictly grounded in the logged timeline below — do not invent actions, hosts, tools, or outcomes that aren't listed.

Operation: {operation.name}
Objective: {operation.objective or 'not specified'}
Emulated threat actor: {operation.threat_actor or 'not specified'}
Status: {operation.status.value if hasattr(operation.status, 'value') else operation.status}

Logged timeline:
{source_material}

Write a narrative (400-600 words) describing the attack path chronologically, calling out which actions were detected by the blue team and which weren't, suitable for inclusion in a red team report."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=1200,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def generate_purple_team_export(operation: RedTeamOperation, timeline_entries: list[RedTeamTimelineEntry]) -> str:
    """Markdown export of the operation timeline for a purple team debrief session — plain data, no AI involved."""
    lines = [
        f"# Purple Team Debrief — {operation.name}",
        "",
        f"**Objective:** {operation.objective or 'not specified'}",
        f"**Emulated threat actor:** {operation.threat_actor or 'not specified'}",
        f"**Status:** {operation.status.value if hasattr(operation.status, 'value') else operation.status}",
        "",
        "| Timestamp | Phase | Action | Host | Tool | Outcome | Detected | ATT&CK |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for e in sorted(timeline_entries, key=lambda x: x.timestamp):
        phase = e.phase.value if hasattr(e.phase, "value") else e.phase
        detected = e.detected.value if hasattr(e.detected, "value") else e.detected
        lines.append(
            f"| {e.timestamp} | {phase} | {e.action} | {e.host or ''} | {e.tool_used or ''} "
            f"| {e.outcome or ''} | {detected} | {e.attack_technique_id or ''} |"
        )
    return "\n".join(lines)
