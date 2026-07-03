"""
MOB-1 — Mobile App Security Static Analyser.

androguard is the primary Android analysis engine: pure Python, no JVM
required, always available once pip-installed (unlike Apktool/JADX/MobSF
which need a JVM or a heavier install). iOS .ipa parsing uses only
zipfile + plistlib (both stdlib), since a full iOS static analysis
engine is a much heavier lift than this platform needs for MASVS L1/L2
checks.

apktool/jadx/trufflehog are wired as OPTIONAL subprocess enrichment via
run_optional_enrichment(), degrading gracefully (same try/except
FileNotFoundError pattern as recon.py's amass/nmap calls) if not
installed on the host — they are not hard dependencies.

This is a best-effort static analyzer, not a certified MASVS audit tool:
exported-component detection is regex-based against the decoded
AndroidManifest.xml text rather than a full binary-XML object model, and
secret/weak-crypto detection is pattern matching against extracted
strings, not full taint analysis.
"""
import logging
import plistlib
import re
import subprocess
import zipfile

from app.core.config import settings

logger = logging.getLogger(__name__)

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key": re.compile(r'(?i)api[_-]?key["\'=:\s]+[0-9a-zA-Z\-_]{16,}'),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |)PRIVATE KEY-----"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "firebase_url": re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
    "generic_bearer_token": re.compile(r"(?i)bearer\s+[0-9a-zA-Z\-_.]{20,}"),
}

WEAK_CRYPTO_PATTERNS = {
    "MD5": re.compile(r"\bMD5\b", re.IGNORECASE),
    "SHA1": re.compile(r"\bSHA-?1\b", re.IGNORECASE),
    "DES": re.compile(r"\bDES\b"),
    "RC4": re.compile(r"\bRC4\b", re.IGNORECASE),
}

# MASVS L1/L2 checklist -- a static control-to-check mapping, same shape
# idea as ComplianceControl's framework seeds in compliance.py.
MASVS_CONTROLS = [
    ("MSTG-STORAGE-1", "App data backup is disabled (android:allowBackup=false / sensitive iOS files excluded from backup)"),
    ("MSTG-PLATFORM-1", "Components (activities/services/providers/receivers) are not exported unless required"),
    ("MSTG-CRYPTO-1", "No known-weak cryptographic algorithms (MD5/SHA1/DES/RC4) referenced"),
    ("MSTG-CODE-2", "App is not marked as debuggable in a production build"),
    ("MSTG-NETWORK-1", "Cleartext traffic is not permitted / TLS validation is not disabled"),
    ("MSTG-AUTH-1", "No hardcoded credentials, API keys, or secrets embedded in the app"),
]
_MASVS_LABELS = dict(MASVS_CONTROLS)


def _scan_strings_for_secrets(strings: list[str]) -> list[dict]:
    hits, seen = [], set()
    for s in strings:
        for name, pattern in SECRET_PATTERNS.items():
            if name in seen:
                continue
            if pattern.search(s):
                seen.add(name)
                hits.append({"type": name, "excerpt": s[:120]})
    return hits


def _scan_strings_for_weak_crypto(strings: list[str]) -> list[dict]:
    hits, seen = [], set()
    for s in strings:
        for algo, pattern in WEAK_CRYPTO_PATTERNS.items():
            if algo in seen:
                continue
            if pattern.search(s):
                seen.add(algo)
                hits.append({"algorithm": algo, "excerpt": s[:120]})
    return hits


def _component_is_exported(manifest_xml: str, tag: str, name: str) -> bool:
    """Best-effort: finds the component's XML block by tag+name and checks its exported attr / intent-filter presence."""
    short_name = re.escape(name.rsplit(".", 1)[-1])
    pattern = re.compile(rf'<{tag}\b[^>]*android:name="[^"]*{short_name}"[^>]*(?:/>|>.*?</{tag}>)', re.DOTALL)
    match = pattern.search(manifest_xml)
    if not match:
        return False
    block = match.group(0)
    exported_match = re.search(r'android:exported="(true|false)"', block)
    if exported_match:
        return exported_match.group(1) == "true"
    return "<intent-filter" in block


def analyze_apk(file_path: str) -> dict:
    """androguard-based Android static analysis."""
    from androguard.misc import AnalyzeAPK

    apk, dex_list, _dx = AnalyzeAPK(file_path)

    manifest_xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", errors="ignore")
    app_tag_match = re.search(r"<application\b[^>]*>", manifest_xml)
    app_tag = app_tag_match.group(0) if app_tag_match else ""

    def _bool_attr(tag_text: str, attr: str) -> str | None:
        m = re.search(rf'android:{attr}="(true|false)"', tag_text)
        return m.group(1) if m else None

    exported_components = []
    for tag, names in (
        ("activity", apk.get_activities()),
        ("service", apk.get_services()),
        ("receiver", apk.get_receivers()),
        ("provider", apk.get_providers()),
    ):
        for name in names:
            if _component_is_exported(manifest_xml, tag, name):
                exported_components.append({"type": tag, "name": name})

    strings: set[str] = set()
    for d in dex_list:
        strings.update(d.get_strings())

    return {
        "package_name": apk.get_package(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": apk.get_permissions(),
        "allow_backup": _bool_attr(app_tag, "allowBackup"),
        "debuggable": _bool_attr(app_tag, "debuggable"),
        "uses_cleartext_traffic": _bool_attr(app_tag, "usesCleartextTraffic"),
        "exported_components": exported_components,
        "secret_hits": _scan_strings_for_secrets(list(strings)),
        "weak_crypto_hits": _scan_strings_for_weak_crypto(list(strings)),
    }


def analyze_ipa(file_path: str) -> dict:
    """Stdlib-only (zipfile + plistlib) iOS .ipa parsing -- no heavy iOS-specific dependency needed for MASVS L1/L2 checks."""
    with zipfile.ZipFile(file_path) as z:
        names = z.namelist()
        plist_name = next((n for n in names if re.match(r"Payload/[^/]+\.app/Info\.plist$", n)), None)
        if not plist_name:
            raise ValueError("No Info.plist found under Payload/*.app/ — not a valid iOS app bundle")
        with z.open(plist_name) as f:
            info = plistlib.load(f)

        strings = []
        for name in names:
            if name.endswith((".plist", ".json", ".js", ".txt", ".strings", ".xml")):
                try:
                    strings.append(z.read(name).decode("utf-8", errors="ignore"))
                except (KeyError, OSError):
                    continue

    ats = info.get("NSAppTransportSecurity") or {}
    ats_allows_arbitrary_loads = bool(ats.get("NSAllowsArbitraryLoads", False))
    url_schemes = [scheme for entry in info.get("CFBundleURLTypes", []) for scheme in entry.get("CFBundleURLSchemes", [])]

    return {
        "package_name": info.get("CFBundleIdentifier"),
        "min_sdk": info.get("MinimumOSVersion"),
        "target_sdk": None,
        "permissions": [k for k in info if k.startswith("NS") and k.endswith("UsageDescription")],
        "allow_backup": None,  # not an Android/iOS-comparable flag; iOS backup exclusion is per-file, not app-wide
        "debuggable": None,
        "uses_cleartext_traffic": "true" if ats_allows_arbitrary_loads else "false",
        "exported_components": [],
        "url_schemes": url_schemes,
        "secret_hits": _scan_strings_for_secrets(strings),
        "weak_crypto_hits": _scan_strings_for_weak_crypto(strings),
    }


def evaluate_masvs_checklist(analysis: dict) -> list[dict]:
    """Turns a raw analyze_apk/analyze_ipa result into MASVS-tagged findings."""
    findings = []

    if str(analysis.get("allow_backup")).lower() == "true":
        findings.append(_finding("MSTG-STORAGE-1", "high", "android:allowBackup is enabled — app data can be extracted via adb backup on a rooted/debug-enabled device."))
    if analysis.get("exported_components"):
        comps = ", ".join(f"{c['type']}:{c['name']}" for c in analysis["exported_components"][:10])
        findings.append(_finding("MSTG-PLATFORM-1", "medium", f"{len(analysis['exported_components'])} component(s) exported without an apparent need: {comps}"))
    if analysis.get("weak_crypto_hits"):
        algos = ", ".join(sorted({h["algorithm"] for h in analysis["weak_crypto_hits"]}))
        findings.append(_finding("MSTG-CRYPTO-1", "medium", f"References to weak cryptographic algorithm(s) found: {algos}."))
    if str(analysis.get("debuggable")).lower() == "true":
        findings.append(_finding("MSTG-CODE-2", "high", "android:debuggable is set to true — must never ship in a production build."))
    if str(analysis.get("uses_cleartext_traffic")).lower() == "true":
        findings.append(_finding("MSTG-NETWORK-1", "high", "Cleartext traffic / arbitrary ATS loads are permitted — traffic can be intercepted without TLS."))
    if analysis.get("secret_hits"):
        types = ", ".join(sorted({h["type"] for h in analysis["secret_hits"]}))
        findings.append(_finding("MSTG-AUTH-1", "critical", f"Hardcoded secret(s) detected in the app binary: {types}."))

    return findings


def _finding(masvs_control: str, severity: str, description: str) -> dict:
    return {
        "masvs_control": masvs_control, "control_label": _MASVS_LABELS.get(masvs_control, masvs_control),
        "severity": severity, "description": description, "status": "open",
    }


def compute_masvs_score(findings: list[dict]) -> int:
    """Percentage of MASVS L1/L2 controls with no open finding -- 100 means every check below passed."""
    total = len(MASVS_CONTROLS)
    failed_controls = {f["masvs_control"] for f in findings}
    passed = total - len(failed_controls)
    return round(100 * passed / total) if total else 0


def run_optional_enrichment(binary: str, args: list[str], timeout: int = 300) -> str | None:
    """Runs an optional external tool (apktool/jadx/trufflehog) if present on PATH. None means 'tool not installed', distinct from a real empty-output run."""
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        return proc.stdout[:4000]
    except FileNotFoundError:
        logger.info(f"`{binary}` not found on PATH — skipping optional enrichment")
        return None
    except subprocess.TimeoutExpired:
        logger.error(f"`{binary}` timed out")
        return None


def run_static_analysis(file_path: str, platform: str) -> dict:
    analysis = analyze_apk(file_path) if platform == "android" else analyze_ipa(file_path)
    findings = evaluate_masvs_checklist(analysis)
    return {"analysis": analysis, "findings": findings, "masvs_score": compute_masvs_score(findings)}


def _claude_client():
    import anthropic
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot generate mobile security executive summary.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def generate_executive_summary(app_label: str, findings: list[dict], masvs_score: int) -> str:
    """MOB-3 — Claude-drafted executive summary grounded in the real findings from this scan."""
    ai = _claude_client()
    finding_lines = [f"- [{f['severity'].upper()}] {f['control_label']}: {f['description']}" for f in findings]
    prompt = f"""Write a 150-200 word executive summary of a mobile app security static analysis for "{app_label}".

MASVS L1/L2 compliance score: {masvs_score}%
Findings:
{chr(10).join(finding_lines) if finding_lines else 'No MASVS findings — the app passed every automated static check run.'}

Cover: overall posture, the single most important issue to fix first (if any), and one closing sentence of encouragement or urgency depending on severity. No preamble, no jargon overload -- a non-technical founder should understand it."""

    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=350, messages=[{"role": "user", "content": prompt}])
    return "".join(block.text for block in response.content if block.type == "text").strip()
