"""
TH-1 — Continuous Threat Hunting.

query_elastic/query_splunk/query_crowdstrike run real REST calls against a
client's own SIEM/EDR, using credentials decrypted via app/core/crypto.py
(the same Fernet pattern as CloudAccount). All three degrade to an empty
result -- never raise -- if the connection isn't configured or the query
fails, since a hunt should never crash on a temporarily-unreachable SIEM.
IoC enrichment and ATT&CK coverage both reuse existing modules rather than
reimplementing that logic a third time in this codebase.
"""
import json
import logging
from datetime import datetime

import anthropic
import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crypto import decrypt_credentials
from app.models.models import HuntHypothesis, HuntHypothesisSource, HuntOperation, HuntFinding, SiemConnection
from app.services.attack_framework import generate_navigator_layer
from app.services.threat_intel import check_shodan, check_censys, check_threat_intel_blocklists

logger = logging.getLogger(__name__)

STARTER_HYPOTHESES = [
    ("Anomalous PowerShell execution chains", "Hunt for encoded/obfuscated PowerShell launched by Office processes",
     "T1059.001", ["EDR", "process logs"], []),
    ("Living-off-the-land binary abuse", "Hunt for suspicious use of certutil/regsvr32/mshta for payload delivery",
     "T1218", ["EDR"], []),
    ("Kerberoasting attempts", "Hunt for abnormal volume of TGS ticket requests for service accounts",
     "T1558.003", ["auth logs", "EDR"], ["fintech", "healthcare"]),
    ("Suspicious scheduled task creation", "Hunt for scheduled tasks created outside change-management windows",
     "T1053.005", ["EDR", "Windows Event Logs"], []),
    ("New local admin account creation", "Hunt for local administrator accounts created without a matching ticket",
     "T1136.001", ["EDR", "auth logs"], []),
    ("DNS tunneling indicators", "Hunt for high-entropy subdomains and abnormal TXT record query volume",
     "T1071.004", ["DNS logs"], []),
    ("Rare outbound protocol usage", "Hunt for outbound connections on non-standard ports from server subnets",
     "T1571", ["netflow", "firewall logs"], []),
    ("Impossible travel logins", "Hunt for the same account authenticating from geographically implausible locations within a short window",
     "T1078", ["auth logs", "IdP logs"], []),
    ("Mass file rename/encryption activity", "Hunt for a burst of file modifications matching ransomware extension patterns",
     "T1486", ["EDR", "file server logs"], []),
    ("Credential dumping via LSASS access", "Hunt for non-standard processes accessing lsass.exe memory",
     "T1003.001", ["EDR"], []),
    ("Exfiltration to cloud storage", "Hunt for large outbound transfers to consumer cloud-storage domains",
     "T1567.002", ["proxy logs", "DLP"], []),
    ("Golden ticket indicators", "Hunt for Kerberos tickets with anomalous lifetimes or missing PAC validation",
     "T1558.001", ["auth logs"], ["fintech"]),
    ("Suspicious registry run-key persistence", "Hunt for new autorun registry entries pointing to temp/appdata paths",
     "T1547.001", ["EDR"], []),
    ("Web shell indicators", "Hunt for newly written script files in web-accessible directories followed by anomalous process spawns",
     "T1505.003", ["EDR", "web server logs"], []),
    ("Brute-force against exposed RDP/SSH", "Hunt for high-volume auth failures against internet-facing RDP/SSH",
     "T1110", ["firewall logs", "auth logs"], []),
    ("Business email compromise indicators", "Hunt for inbox rule creation that auto-forwards/deletes finance-related emails",
     "T1114.003", ["email logs"], ["fintech"]),
    ("Container escape indicators", "Hunt for privileged container processes accessing host filesystem paths",
     "T1611", ["EDR", "container runtime logs"], ["technology"]),
    ("Unusual data staging", "Hunt for large archive files (zip/rar/7z) created in temp directories shortly before network transfers",
     "T1560", ["EDR", "file server logs"], []),
    ("Anomalous service account interactive logon", "Hunt for service accounts authenticating interactively rather than via their expected scheduled process",
     "T1078.002", ["auth logs"], []),
    ("Firmware/bootkit persistence indicators", "Hunt for unsigned UEFI/bootloader modifications on endpoint fleet",
     "T1542", ["EDR"], ["technology"]),
]


def _claude_client() -> anthropic.Anthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate AI content.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def seed_hypothesis_library(db: Session) -> int:
    """Idempotent: seeds the shared hypothesis library once, regardless of how many clients exist."""
    if db.query(HuntHypothesis).count() > 0:
        return 0
    created = 0
    for title, description, technique, data_sources, industries in STARTER_HYPOTHESES:
        db.add(HuntHypothesis(title=title, description=description, attack_technique=technique,
                               data_sources=data_sources, industries=industries,
                               source=HuntHypothesisSource.manual, created_at=datetime.utcnow()))
        created += 1
    db.commit()
    return created


def generate_hypothesis(client_industry: str, recent_cti: list[str] | None = None) -> dict:
    """Claude-drafted hunt hypothesis, tailored to the client's industry and any recent CTI notes provided -- never invents specific incidents."""
    client_ai = _claude_client()
    recent_cti = recent_cti or []

    prompt = f"""Propose ONE new threat-hunting hypothesis for a client in the {client_industry or 'technology'} industry.

{"Recent CTI context to consider: " + "; ".join(recent_cti) if recent_cti else "No specific recent CTI context provided — propose a generally high-value hypothesis for this industry."}

Respond as JSON only, no markdown fencing, with exactly these keys: "title" (short), "description" (2-3 sentences), "attack_technique" (a single MITRE ATT&CK technique ID), "data_sources" (a list of 1-4 short data source names)."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(block.text for block in response.content if block.type == "text").strip()
    try:
        return json.loads(text)
    except ValueError:
        logger.warning(f"generate_hypothesis got non-JSON response, wrapping raw text: {text[:200]}")
        return {"title": "AI-generated hypothesis", "description": text, "attack_technique": None, "data_sources": []}


def query_elastic(connection: SiemConnection, kql_query: str, index: str = "*", size: int = 50, timeout: int = 20) -> list[dict]:
    """Real Elasticsearch _search query. Degrades to [] if unconfigured or the request fails."""
    if not connection or not connection.base_url:
        return []
    try:
        creds = decrypt_credentials(connection.encrypted_credentials)
    except ValueError as e:
        logger.warning(f"Could not decrypt Elastic credentials for connection {connection.id}: {e}")
        return []
    if not creds.get("api_key"):
        return []

    try:
        resp = httpx.post(
            f"{connection.base_url.rstrip('/')}/{index}/_search",
            json={"query": {"query_string": {"query": kql_query}}, "size": size},
            headers={"Authorization": f"ApiKey {creds['api_key']}"}, timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.warning(f"Elastic query failed: {e}")
        return []
    return [hit.get("_source", {}) for hit in data.get("hits", {}).get("hits", [])]


def query_splunk(connection: SiemConnection, spl_query: str, timeout: int = 30) -> list[dict]:
    """Real Splunk search export (oneshot). Degrades to [] if unconfigured or the request fails."""
    if not connection or not connection.base_url:
        return []
    try:
        creds = decrypt_credentials(connection.encrypted_credentials)
    except ValueError as e:
        logger.warning(f"Could not decrypt Splunk credentials for connection {connection.id}: {e}")
        return []
    if not (creds.get("username") and creds.get("password")):
        return []

    try:
        resp = httpx.post(
            f"{connection.base_url.rstrip('/')}/services/search/jobs/export",
            data={"search": f"search {spl_query}", "output_mode": "json"},
            auth=(creds["username"], creds["password"]), timeout=timeout,
        )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        logger.warning(f"Splunk query failed: {e}")
        return []

    results = []
    for line in resp.text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if "result" in obj:
            results.append(obj["result"])
    return results


def query_crowdstrike(connection: SiemConnection, filter_query: str, timeout: int = 20) -> list[dict]:
    """Real CrowdStrike Falcon OAuth2 + Detections API query. Degrades to [] if unconfigured or the request fails."""
    if not connection or not connection.base_url:
        return []
    try:
        creds = decrypt_credentials(connection.encrypted_credentials)
    except ValueError as e:
        logger.warning(f"Could not decrypt CrowdStrike credentials for connection {connection.id}: {e}")
        return []
    if not (creds.get("client_id") and creds.get("client_secret")):
        return []

    base = connection.base_url.rstrip("/")
    try:
        token_resp = httpx.post(
            f"{base}/oauth2/token",
            data={"client_id": creds["client_id"], "client_secret": creds["client_secret"]}, timeout=timeout,
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token")
        if not token:
            return []

        resp = httpx.get(
            f"{base}/detects/queries/detects/v1", params={"filter": filter_query},
            headers={"Authorization": f"Bearer {token}"}, timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.warning(f"CrowdStrike query failed: {e}")
        return []
    return data.get("resources", [])


def enrich_ioc(ioc_value: str, ioc_type: str) -> dict:
    """Reuses threat_intel.py's existing IP-reputation checks directly rather than reimplementing IoC enrichment."""
    if ioc_type != "ip":
        return {"ioc_value": ioc_value, "ioc_type": ioc_type, "enriched": False,
                "note": f"Enrichment is only available for IP indicators in this build (got '{ioc_type}')."}

    shodan_hits = check_shodan([ioc_value])
    censys_hits = check_censys([ioc_value])
    blocklist_hits = check_threat_intel_blocklists([ioc_value])
    return {
        "ioc_value": ioc_value, "ioc_type": ioc_type, "enriched": True,
        "shodan": shodan_hits, "censys": censys_hits, "blocklists": blocklist_hits,
        "flagged": bool(shodan_hits or censys_hits or blocklist_hits),
    }


def generate_hunt_report(hunt: HuntOperation, findings: list[HuntFinding]) -> str:
    """Claude-written hunt report, grounded strictly in the recorded findings -- weekly-digest-style grounding discipline."""
    client_ai = _claude_client()

    if not findings:
        source_material = "No findings were recorded for this hunt."
    else:
        lines = [f"- [{f.severity.value if hasattr(f.severity, 'value') else f.severity}] {f.title}: "
                  f"{f.description or 'no description'} (confirmed: {f.confirmed}, escalated to IR: {f.escalated_to_ir})"
                  for f in findings]
        source_material = "\n".join(lines)

    hypothesis_title = hunt.hypothesis.title if hunt.hypothesis else "Unknown hypothesis"
    outcome = hunt.outcome.value if hasattr(hunt.outcome, "value") else hunt.outcome

    prompt = f"""Write a threat hunt report (300-450 words), grounded strictly in the findings below — do not invent findings, IoCs, or outcomes not listed.

Hypothesis hunted: {hypothesis_title}
Outcome: {outcome or 'not yet recorded'}
Hours spent: {hunt.hours_spent}

Findings:
{source_material}

Cover: what was hunted and why, what was found (or genuinely not found), and recommended next steps."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=900,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def compute_attck_coverage(hunts: list[HuntOperation]) -> dict:
    """Builds an ATT&CK Navigator layer from completed hunts' underlying hypothesis techniques -- reuses attack_framework directly."""
    counts: dict[str, int] = {}
    for hunt in hunts:
        technique = hunt.hypothesis.attack_technique if hunt.hypothesis else None
        if technique:
            counts[technique] = counts.get(technique, 0) + 1
    return generate_navigator_layer(counts, name="Threat Hunting Coverage",
                                     description="Techniques covered by completed hunt operations.")
