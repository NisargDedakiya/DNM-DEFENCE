"""
IOT-1 — Hardware & IoT Firmware Analyzer.

Extraction (binwalk) and binary hardening enrichment (checksec) are both
optional subprocess tools that degrade gracefully -- not just on
FileNotFoundError (binary missing) but also on a non-zero exit (a broken
or incompatible local binwalk install), since either way the rest of the
analysis pipeline should still run against whatever bytes are available.
"""
import logging
import os
import re
import subprocess

import httpx

from app.core.config import settings
from app.services.mobile_sast import SECRET_PATTERNS

logger = logging.getLogger(__name__)

_COMPONENT_SIGNATURES = {
    "BusyBox": re.compile(r"BusyBox\s+v?(\d+\.\d+\.\d+)"),
    "Linux kernel": re.compile(r"Linux version (\d+\.\d+\.\d+)"),
    "OpenSSL": re.compile(r"OpenSSL (\d+\.\d+\.\d+\w*)"),
    "Dropbear": re.compile(r"Dropbear[_-]?v?(\d{4}\.\d+)"),
    "uClibc": re.compile(r"uClibc[- ](\d+\.\d+\.\d+)"),
    "lighttpd": re.compile(r"lighttpd/(\d+\.\d+\.\d+)"),
    "U-Boot": re.compile(r"U-Boot (\d{4}\.\d+)"),
}

_PRINTABLE_STRINGS_RE = re.compile(rb"[\x20-\x7e]{4,}")

_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_printable_strings(data: bytes) -> str:
    """Equivalent of the Unix `strings` command -- pulls runs of printable ASCII out of a binary blob."""
    return "\n".join(m.decode("ascii", errors="ignore") for m in _PRINTABLE_STRINGS_RE.findall(data))


def run_binwalk_extraction(file_path: str, output_dir: str, timeout: int = 300) -> dict:
    """Runs `binwalk -e` to carve out an embedded filesystem. Degrades gracefully (extracted=False) if binwalk is missing, broken, or times out -- never raises."""
    os.makedirs(output_dir, exist_ok=True)
    try:
        proc = subprocess.run(
            ["binwalk", "-e", "--directory", output_dir, file_path],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.info("`binwalk` not found on PATH — skipping firmware extraction")
        return {"extracted": False, "output_dir": None, "raw_output": None}
    except subprocess.TimeoutExpired:
        logger.error("`binwalk` timed out during extraction")
        return {"extracted": False, "output_dir": None, "raw_output": None}

    if proc.returncode != 0:
        logger.info(f"binwalk exited non-zero — treating extraction as unavailable: {proc.stderr[:300]}")
        return {"extracted": False, "output_dir": None, "raw_output": proc.stdout[:2000]}

    return {"extracted": True, "output_dir": output_dir, "raw_output": proc.stdout[:4000]}


def scan_extracted_files_for_secrets(directory: str, max_files: int = 500) -> list[dict]:
    """Walks extracted firmware files looking for hardcoded secrets, reusing mobile_sast.py's SECRET_PATTERNS."""
    hits = []
    scanned = 0
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if scanned >= max_files:
                return hits
            path = os.path.join(root, fname)
            try:
                with open(path, "rb") as f:
                    data = f.read(2_000_000)  # cap per-file read to keep this bounded
            except OSError:
                continue
            scanned += 1
            text = extract_printable_strings(data)
            for name, pattern in SECRET_PATTERNS.items():
                match = pattern.search(text)
                if match:
                    hits.append({"type": name, "file": os.path.relpath(path, directory), "excerpt": match.group(0)[:120]})
    return hits


def identify_components(text_blob: str) -> dict:
    """Signature-matches common embedded-firmware component/version strings out of extracted (or raw) text."""
    components = {}
    for name, pattern in _COMPONENT_SIGNATURES.items():
        match = pattern.search(text_blob)
        if match:
            components[name] = match.group(1)
    return components


def check_library_cves(component_versions: dict[str, str], timeout: int = 15) -> list[dict]:
    """NVD API v2 keyword search per identified component -- free, keyless (NVD_API_KEY optional, lifts rate limit)."""
    headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
    hits = []
    for component, version in component_versions.items():
        try:
            resp = httpx.get(
                _NVD_CVE_URL, params={"keywordSearch": f"{component} {version}", "resultsPerPage": 5},
                headers=headers, timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.info(f"NVD lookup skipped for {component} {version}: {e}")
            continue
        for vuln in data.get("vulnerabilities", []):
            cve = vuln["cve"]
            description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            hits.append({"component": component, "version": version, "cve_id": cve.get("id"), "description": description})
    return hits


def run_checksec(binary_path: str, timeout: int = 30) -> dict | None:
    """Optional checksec enrichment (NX/PIE/RELRO/canary flags) for an extracted ELF binary. None means the tool isn't installed."""
    try:
        proc = subprocess.run(["checksec", "--file", binary_path, "--format", "json"],
                               capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        logger.info("`checksec` not found on PATH — skipping binary hardening enrichment")
        return None
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    import json
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return None


def generate_firmware_summary(findings: dict) -> str:
    """Claude-written executive summary grounded strictly in the recorded component/secret/CVE findings."""
    import anthropic
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate firmware executive summary.")
    client_ai = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    components = findings.get("components", {})
    secrets = findings.get("secrets", [])
    cves = findings.get("cves", [])

    prompt = f"""Write a firmware security executive summary (250-400 words), grounded strictly in the findings below — do not invent components, secrets, or CVEs not listed.

Identified components: {', '.join(f'{k} {v}' for k, v in components.items()) or 'none identified'}
Hardcoded secrets found: {len(secrets)} ({', '.join(s['type'] for s in secrets[:10]) or 'none'})
Known CVEs matched to identified components: {len(cves)} ({', '.join(c['cve_id'] for c in cves[:10] if c.get('cve_id')) or 'none'})

Cover: what was found, business risk, and prioritized remediation steps."""

    response = client_ai.messages.create(
        model=settings.ANTHROPIC_MODEL, max_tokens=800,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()
