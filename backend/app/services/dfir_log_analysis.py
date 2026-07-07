"""
DFIR-2 — Forensic Log Analyzer.

Parses cloud audit logs (AWS CloudTrail, Azure Activity Log, GCP Audit
Log — all JSON), generic line-based logs (syslog, nginx/apache combined
format, Palo Alto CSV) via regex, and Windows EVTX via python-evtx, into
one normalized event shape:
    {"timestamp": str, "event_type": str, "source_ip": str|None,
     "user": str|None, "host": str|None, "outcome": str|None, "raw": str}
Anomaly detection and IoC extraction then run uniformly over that shape
regardless of source format.
"""
import json
import logging
import re
from collections import defaultdict
from datetime import datetime

import anthropic

from app.core.config import settings

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b")

_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\S+?):\s*(?P<msg>.*)$"
)
_COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})'
)


def _claude_client() -> anthropic.Anthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate AI narrative content.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def parse_cloudtrail_json(data: dict) -> list[dict]:
    """
    AWS CloudTrail export -- {"Records": [...]}. Failure detection covers both
    API-call errors (errorCode) and console login failures, which AWS reports
    via responseElements.ConsoleLogin == "Failure" with no errorCode at all --
    missing that case would silently blind repeated-auth-failure detection to
    the most common real-world brute-force scenario (console login attempts).
    """
    events = []
    for rec in data.get("Records", []):
        user_identity = rec.get("userIdentity", {}) or {}
        response_elements = rec.get("responseElements", {}) or {}
        failed = bool(rec.get("errorCode")) or response_elements.get("ConsoleLogin") == "Failure"
        events.append({
            "timestamp": rec.get("eventTime"),
            "event_type": rec.get("eventName"),
            "source_ip": rec.get("sourceIPAddress"),
            "user": user_identity.get("userName") or user_identity.get("arn"),
            "host": rec.get("eventSource"),
            "outcome": "failure" if failed else "success",
            "raw": json.dumps(rec),
        })
    return events


def parse_azure_activity_log(data: dict) -> list[dict]:
    """Azure Activity Log export -- {"value": [...]}."""
    events = []
    for rec in data.get("value", []):
        op = rec.get("operationName", {}) or {}
        status = rec.get("status", {}) or {}
        events.append({
            "timestamp": rec.get("eventTimestamp"),
            "event_type": op.get("value") or op.get("localizedValue"),
            "source_ip": rec.get("callerIpAddress"),
            "user": rec.get("caller"),
            "host": rec.get("resourceId"),
            "outcome": "success" if status.get("value") == "Succeeded" else "failure",
            "raw": json.dumps(rec),
        })
    return events


def parse_gcp_audit_log(data: dict) -> list[dict]:
    """GCP Audit Log export -- either {"entries": [...]} or a bare top-level list."""
    entries = data.get("entries", data) if isinstance(data, dict) else data
    events = []
    for rec in entries:
        payload = rec.get("protoPayload", {}) or {}
        auth_info = payload.get("authenticationInfo", {}) or {}
        req_meta = payload.get("requestMetadata", {}) or {}
        status = payload.get("status", {}) or {}
        events.append({
            "timestamp": rec.get("timestamp"),
            "event_type": payload.get("methodName"),
            "source_ip": req_meta.get("callerIp"),
            "user": auth_info.get("principalEmail"),
            "host": payload.get("resourceName"),
            "outcome": "failure" if status.get("code") else "success",
            "raw": json.dumps(rec),
        })
    return events


def parse_syslog(text: str) -> list[dict]:
    """Generic syslog line format, e.g. sshd failed-password lines."""
    events = []
    for line in text.splitlines():
        m = _SYSLOG_RE.match(line.strip())
        if not m:
            continue
        msg = m.group("msg")
        user_match = re.search(r"user (\S+)", msg) or re.search(r"for (\S+) from", msg)
        ip_match = _IPV4_RE.search(msg)
        events.append({
            "timestamp": m.group("ts"),
            "event_type": m.group("proc"),
            "source_ip": ip_match.group(0) if ip_match else None,
            "user": user_match.group(1) if user_match else None,
            "host": m.group("host"),
            "outcome": "failure" if "fail" in msg.lower() or "invalid" in msg.lower() else "success",
            "raw": line,
        })
    return events


def parse_web_access_log(text: str) -> list[dict]:
    """Nginx/Apache combined log format."""
    events = []
    for line in text.splitlines():
        m = _COMBINED_LOG_RE.match(line.strip())
        if not m:
            continue
        events.append({
            "timestamp": m.group("ts"),
            "event_type": f"{m.group('method')} {m.group('path')}",
            "source_ip": m.group("ip"),
            "user": None,
            "host": None,
            "outcome": "success" if m.group("status").startswith(("2", "3")) else "failure",
            "raw": line,
        })
    return events


def parse_palo_alto_log(text: str) -> list[dict]:
    """PAN-OS CSV log export -- receive_time,src,dst,action,... (position-tolerant subset)."""
    events = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(",")
        if len(fields) < 4:
            continue
        events.append({
            "timestamp": fields[0].strip() or None,
            "event_type": "traffic",
            "source_ip": fields[1].strip() if len(fields) > 1 else None,
            "user": None,
            "host": fields[2].strip() if len(fields) > 2 else None,
            "outcome": "failure" if len(fields) > 3 and "deny" in fields[3].lower() else "success",
            "raw": line,
        })
    return events


def parse_evtx(file_path: str) -> list[dict]:
    """Windows EVTX event log via python-evtx. Degrades to an empty list if the file isn't a valid EVTX."""
    import Evtx.Evtx as evtx
    from lxml import etree

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    try:
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                try:
                    root = etree.fromstring(record.xml().encode("utf-8"))
                except etree.XMLSyntaxError:
                    continue
                system = root.find("e:System", ns)
                if system is None:
                    continue
                event_id = system.findtext("e:EventID", default=None, namespaces=ns)
                time_created = system.find("e:TimeCreated", ns)
                timestamp = time_created.get("SystemTime") if time_created is not None else None
                computer = system.findtext("e:Computer", default=None, namespaces=ns)

                event_data = {}
                data_el = root.find("e:EventData", ns)
                if data_el is not None:
                    for d in data_el.findall("e:Data", ns):
                        name = d.get("Name")
                        if name:
                            event_data[name] = d.text

                events.append({
                    "timestamp": timestamp,
                    "event_type": f"EventID {event_id}",
                    "source_ip": event_data.get("IpAddress"),
                    "user": event_data.get("TargetUserName") or event_data.get("SubjectUserName"),
                    "host": computer,
                    "outcome": "failure" if event_id == "4625" else ("success" if event_id == "4624" else None),
                    "raw": json.dumps(event_data),
                })
    except FileNotFoundError:
        raise
    except Exception as e:
        logger.warning(f"Failed to parse EVTX file {file_path}: {e}")
    return events


def detect_auth_anomalies(events: list[dict], failure_threshold: int = 5,
                           off_hours_start: int = 22, off_hours_end: int = 6) -> list[dict]:
    """Heuristic anomaly detection: repeated auth failures per user/IP, and off-hours access."""
    anomalies = []
    failures_by_key = defaultdict(list)

    for e in events:
        if e.get("outcome") != "failure":
            continue
        key = e.get("user") or e.get("source_ip")
        if key:
            failures_by_key[key].append(e)

    for key, fails in failures_by_key.items():
        if len(fails) >= failure_threshold:
            anomalies.append({
                "anomaly_type": "repeated_auth_failure", "subject": key, "count": len(fails),
                "detail": f"{len(fails)} failed authentication events for '{key}'",
            })

    for e in events:
        if e.get("outcome") != "success" or not e.get("timestamp"):
            continue
        hour = _extract_hour(e["timestamp"])
        if hour is None:
            continue
        if hour >= off_hours_start or hour < off_hours_end:
            anomalies.append({
                "anomaly_type": "off_hours_access", "subject": e.get("user") or e.get("source_ip") or "unknown",
                "count": 1, "detail": f"Successful access at {hour:02d}:00 UTC by '{e.get('user') or e.get('source_ip')}'",
            })

    return anomalies


def _extract_hour(timestamp: str) -> int | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(timestamp, fmt).hour
        except ValueError:
            continue
    return None


def extract_iocs(events: list[dict]) -> list[dict]:
    """Regex-extracts IPs, domains, and hashes from event source IPs and raw payloads."""
    seen = set()
    iocs = []
    for e in events:
        candidates = []
        if e.get("source_ip"):
            candidates.append(("ip", e["source_ip"]))
        raw = e.get("raw", "") or ""
        candidates += [("ip", m) for m in _IPV4_RE.findall(raw)]
        candidates += [("domain", m) for m in _DOMAIN_RE.findall(raw) if not _IPV4_RE.match(m)]
        candidates += [("hash", m) for m in _HASH_RE.findall(raw)]

        for ioc_type, value in candidates:
            dedup = (ioc_type, value)
            if dedup in seen:
                continue
            seen.add(dedup)
            iocs.append({"ioc_type": ioc_type, "value": value, "context": e.get("event_type") or ""})
    return iocs


def generate_log_narrative(events: list[dict], anomalies: list[dict]) -> str:
    """Claude-written narrative summarizing the parsed logs and detected anomalies -- grounded strictly in the real parsed data."""
    client_ai = _claude_client()

    if not events:
        source_material = "No events were successfully parsed from the uploaded log."
    else:
        sample = events[:20]
        event_lines = [f"- [{e.get('timestamp')}] {e.get('event_type')} user={e.get('user') or 'n/a'} "
                        f"ip={e.get('source_ip') or 'n/a'} outcome={e.get('outcome') or 'n/a'}" for e in sample]
        anomaly_lines = [f"- {a['anomaly_type']}: {a['detail']}" for a in anomalies]
        source_material = (
            f"Total events parsed: {len(events)} (showing first {len(sample)}):\n{chr(10).join(event_lines)}\n\n"
            f"Detected anomalies:\n{chr(10).join(anomaly_lines) if anomaly_lines else '  none'}"
        )

    prompt = f"""Write a forensic log analysis narrative (300-450 words), grounded strictly in the parsed log data below — do not invent events, users, or IPs not listed.

{source_material}

Cover: what the logs show chronologically, which anomalies matter most and why, and recommended next investigative steps."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=900,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()
