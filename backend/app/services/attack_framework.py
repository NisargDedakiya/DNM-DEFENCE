"""
Shared MITRE ATT&CK reference data, used by Red Team Operations (RT-1) and
Threat Hunting (TH-1) so the technique-catalogue and Navigator-layer-export
logic isn't duplicated between them.

Technique IDs are free text everywhere in this platform -- analysts are
never restricted to the bundled list below. The bundled set (14 Enterprise
tactics + ~40 common techniques) exists only to power heatmap/coverage
visualizations with sane labels out of the box. fetch_technique_name()
does a best-effort live lookup against MITRE's own public `cti` GitHub
repo (a plain JSON file, no TAXII protocol, no API key) to resolve a name
for a technique ID that isn't in the bundled set; it degrades to just
echoing the ID back if the fetch fails.
"""
import logging

import httpx

logger = logging.getLogger(__name__)

# The 14 MITRE ATT&CK Enterprise tactics, in kill-chain order.
ATTACK_TACTICS = [
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
]

# A representative, curated set spanning every tactic above -- enough to make
# the heatmap legible out of the box. Not exhaustive; real engagements will
# use technique IDs well beyond this list, which is why lookups/tagging never
# validate against it.
ATTACK_TECHNIQUES = {
    "T1595": ("reconnaissance", "Active Scanning"),
    "T1589": ("reconnaissance", "Gather Victim Identity Information"),
    "T1583": ("resource_development", "Acquire Infrastructure"),
    "T1584": ("resource_development", "Compromise Infrastructure"),
    "T1566": ("initial_access", "Phishing"),
    "T1566.001": ("initial_access", "Phishing: Spearphishing Attachment"),
    "T1190": ("initial_access", "Exploit Public-Facing Application"),
    "T1195": ("initial_access", "Supply Chain Compromise"),
    "T1059": ("execution", "Command and Scripting Interpreter"),
    "T1059.001": ("execution", "PowerShell"),
    "T1204": ("execution", "User Execution"),
    "T1053": ("persistence", "Scheduled Task/Job"),
    "T1547": ("persistence", "Boot or Logon Autostart Execution"),
    "T1136": ("persistence", "Create Account"),
    "T1078": ("privilege_escalation", "Valid Accounts"),
    "T1068": ("privilege_escalation", "Exploitation for Privilege Escalation"),
    "T1055": ("defense_evasion", "Process Injection"),
    "T1070": ("defense_evasion", "Indicator Removal"),
    "T1027": ("defense_evasion", "Obfuscated Files or Information"),
    "T1562": ("defense_evasion", "Impair Defenses"),
    "T1003": ("credential_access", "OS Credential Dumping"),
    "T1110": ("credential_access", "Brute Force"),
    "T1558": ("credential_access", "Steal or Forge Kerberos Tickets"),
    "T1087": ("discovery", "Account Discovery"),
    "T1082": ("discovery", "System Information Discovery"),
    "T1018": ("discovery", "Remote System Discovery"),
    "T1021": ("lateral_movement", "Remote Services"),
    "T1550": ("lateral_movement", "Use Alternate Authentication Material"),
    "T1550.002": ("lateral_movement", "Pass the Hash"),
    "T1560": ("collection", "Archive Collected Data"),
    "T1114": ("collection", "Email Collection"),
    "T1071": ("command_and_control", "Application Layer Protocol"),
    "T1105": ("command_and_control", "Ingress Tool Transfer"),
    "T1572": ("command_and_control", "Protocol Tunneling"),
    "T1041": ("exfiltration", "Exfiltration Over C2 Channel"),
    "T1567": ("exfiltration", "Exfiltration Over Web Service"),
    "T1486": ("impact", "Data Encrypted for Impact"),
    "T1489": ("impact", "Service Stop"),
}

_MITRE_CTI_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
_technique_name_cache: dict[str, str] = {}


def fetch_technique_name(technique_id: str, timeout: int = 15) -> str:
    """Resolves a human-readable name for a technique ID: bundled list first, then a cached live lookup, then the raw ID."""
    if technique_id in ATTACK_TECHNIQUES:
        return ATTACK_TECHNIQUES[technique_id][1]
    if technique_id in _technique_name_cache:
        return _technique_name_cache[technique_id]

    try:
        resp = httpx.get(_MITRE_CTI_URL, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.info(f"ATT&CK technique name lookup skipped for {technique_id}: {e}")
        return technique_id

    base_id = technique_id.split(".")[0]
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id") in (technique_id, base_id):
                name = obj.get("name", technique_id)
                _technique_name_cache[technique_id] = name
                return name

    _technique_name_cache[technique_id] = technique_id
    return technique_id


def generate_navigator_layer(technique_counts: dict[str, int], name: str = "Track 1 coverage",
                              description: str = "") -> dict:
    """
    Produces a real ATT&CK Navigator layer file (the JSON format Navigator
    itself loads: https://github.com/mitre-attack/attack-navigator).
    technique_counts: {"T1566.001": 3, "T1078": 1, ...}
    """
    max_count = max(technique_counts.values()) if technique_counts else 1
    techniques = []
    for technique_id, count in technique_counts.items():
        techniques.append({
            "techniqueID": technique_id,
            "score": count,
            "comment": f"{count} occurrence(s)",
        })
    return {
        "name": name,
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": max_count},
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
    }
