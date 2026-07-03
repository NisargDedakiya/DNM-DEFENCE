"""
MOB-2 — Mobile API Traffic Interceptor Dashboard.

Ingests a HAR (HTTP Archive) file -- the standard export format from
Burp Suite, Chrome DevTools, mitmproxy, and Charles -- instead of
integrating with Burp Suite Pro's REST API directly (not something this
platform can run). Point any of those tools at the mobile app's traffic,
export a HAR, and import it here.
"""
import json
import re
from urllib.parse import urlparse, parse_qs

SENSITIVE_DATA_PATTERNS = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "api_key_param": re.compile(r'(?i)(api[_-]?key|access[_-]?token|secret)=[^&\s"\']{8,}'),
}


def parse_har(har_content: dict | str) -> list[dict]:
    """Parses a HAR file's entries into a flat list of request/response summaries."""
    data = json.loads(har_content) if isinstance(har_content, str) else har_content
    entries = data.get("log", {}).get("entries", [])
    parsed = []
    for entry in entries:
        req = entry.get("request", {}) or {}
        res = entry.get("response", {}) or {}
        parsed.append({
            "method": req.get("method"),
            "url": req.get("url"),
            "request_headers": {h["name"]: h["value"] for h in req.get("headers", [])},
            "request_body": (req.get("postData") or {}).get("text", "") or "",
            "status": res.get("status"),
            "response_headers": {h["name"]: h["value"] for h in res.get("headers", [])},
            "response_body": (res.get("content") or {}).get("text", "") or "",
        })
    return parsed


def discover_endpoints(entries: list[dict]) -> list[dict]:
    """Endpoint auto-discovery -- host/path/method/params from HAR entries, deduped by (method, host, path)."""
    seen = set()
    endpoints = []
    for e in entries:
        url = e.get("url") or ""
        if not url:
            continue
        parsed = urlparse(url)
        key = (e.get("method"), parsed.netloc, parsed.path)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append({
            "method": e.get("method"), "host": parsed.netloc, "path": parsed.path,
            "query_params": sorted(parse_qs(parsed.query).keys()),
        })
    return endpoints


def detect_sensitive_data(entries: list[dict]) -> list[dict]:
    """Regex-scans request/response bodies and headers for tokens/PII -- flags where sensitive data appears in transit."""
    hits = []
    for e in entries:
        haystacks = {
            "request_body": e.get("request_body", "") or "",
            "response_body": e.get("response_body", "") or "",
            "request_headers": str(e.get("request_headers", {})),
        }
        for location, text in haystacks.items():
            if not text:
                continue
            for kind, pattern in SENSITIVE_DATA_PATTERNS.items():
                if pattern.search(text):
                    hits.append({"url": e.get("url"), "location": location, "type": kind})
    return hits


def classify_auth_headers(entries: list[dict]) -> dict:
    """Splits discovered endpoint URLs into authenticated vs. unauthenticated based on Authorization/Cookie header presence."""
    authenticated, unauthenticated = set(), set()
    for e in entries:
        headers = {k.lower(): v for k, v in (e.get("request_headers") or {}).items()}
        url = e.get("url")
        if not url:
            continue
        if "authorization" in headers or "cookie" in headers:
            authenticated.add(url)
        else:
            unauthenticated.add(url)
    return {"authenticated_endpoints": sorted(authenticated), "unauthenticated_endpoints": sorted(unauthenticated)}


def generate_openapi_lite(endpoints: list[dict]) -> dict:
    """Auto-generated OpenAPI-lite JSON doc from discovered endpoints -- a starting point for real spec authoring, not a full spec."""
    paths: dict = {}
    for ep in endpoints:
        path = ep["path"] or "/"
        paths.setdefault(path, {})
        method = (ep["method"] or "get").lower()
        paths[path][method] = {
            "summary": f"Discovered via HAR import ({ep['host']})",
            "parameters": [{"name": p, "in": "query"} for p in ep.get("query_params", [])],
        }
    return {"openapi": "3.0.0", "info": {"title": "Auto-discovered mobile API surface", "version": "0.1.0"}, "paths": paths}


def analyze_har_import(har_content: dict | str) -> dict:
    entries = parse_har(har_content)
    endpoints = discover_endpoints(entries)
    return {
        "endpoint_count": len(endpoints),
        "discovered_endpoints": endpoints,
        "sensitive_data_hits": detect_sensitive_data(entries),
        "auth_classification": classify_auth_headers(entries),
        "openapi_lite": generate_openapi_lite(endpoints),
    }
