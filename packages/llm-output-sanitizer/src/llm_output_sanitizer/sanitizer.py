"""
Core sanitization/validation logic. See the package README for usage.

Design principles:
  - No network calls unless the caller explicitly opts into the semantic
    PII layer and passes credentials themselves -- this library never
    reads environment variables or makes assumptions about how it's
    deployed.
  - Detection functions never mutate or drop content silently except
    strip_xss (whose entire job is to remove markup) -- PII/leakage
    detection only reports findings, leaving the decision to redact to
    the caller.
"""
import re
from typing import Any

import bleach
from jsonschema import Draft202012Validator

# Conservative default: no HTML tags allowed through at all. Callers who
# need a richer allowlist (e.g. <b>/<i>/<a>) can call bleach.clean directly.
_ALLOWED_TAGS: list[str] = []
_ALLOWED_ATTRS: dict = {}

# bleach.clean(strip=True) removes tags but keeps an element's inner text
# (e.g. "<script>alert(1)</script>" becomes the inert-but-still-visible
# "alert(1)") -- safe against execution, but script/style bodies are noise
# a sanitizer should drop entirely rather than leave in the output.
_SCRIPT_STYLE_BLOCK_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)

PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone_us": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "phone_intl": re.compile(r"\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
    "aadhaar_in": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "ssn_us": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}

# Phrases that show up disproportionately often when a model has leaked
# its own system prompt rather than answering the user's actual question.
# Not exhaustive -- a heuristic first line of defense, not a proof.
_LEAKAGE_PHRASES = [
    "you are a helpful assistant",
    "you are an ai assistant",
    "as an ai language model",
    "my system prompt",
    "my instructions are",
    "i was instructed to",
    "here are my instructions",
    "system prompt:",
    "developer message:",
]


def strip_xss(text: str) -> str:
    """Strips all HTML/script markup by default (see _ALLOWED_TAGS), including the body of <script>/<style> blocks. Safe to call on plain text -- it's a no-op there."""
    if not text:
        return text
    text = _SCRIPT_STYLE_BLOCK_RE.sub("", text)
    return bleach.clean(text, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True)


def detect_pii(text: str) -> list[dict]:
    """Regex-based PII detection across common formats. First line of defense, not a certified PII engine -- see detect_pii_semantic for a deeper (opt-in, key-gated) layer."""
    if not text:
        return []
    hits = []
    for kind, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            hits.append({"type": kind, "match": match.group(0)})
    return hits


def detect_pii_semantic(text: str, anthropic_api_key: str, model: str = "claude-sonnet-4-6") -> list[dict]:
    """
    Optional semantic PII layer using Claude, for PII that doesn't match a
    fixed pattern (e.g. a full name + address in prose). Requires the
    `semantic` extra (`pip install llm-output-sanitizer[semantic]`) and an
    explicit API key from the caller -- this function never reads
    environment variables itself.
    """
    import anthropic

    if not text.strip():
        return []

    client = anthropic.Anthropic(api_key=anthropic_api_key)
    prompt = f"""List any personally identifiable information (PII) present in the text below: full names, addresses, phone numbers, government ID numbers, dates of birth, or similarly sensitive personal data. Respond with one item per line in the format "TYPE: exact matched text". If none, respond with "NONE".

Text:
{text[:4000]}"""

    response = client.messages.create(model=model, max_tokens=500, messages=[{"role": "user", "content": prompt}])
    reply = "".join(block.text for block in response.content if block.type == "text").strip()

    if reply.upper() == "NONE":
        return []

    hits = []
    for line in reply.splitlines():
        if ":" in line:
            kind, _, value = line.partition(":")
            value = value.strip()
            if value:
                hits.append({"type": kind.strip().lower().replace(" ", "_"), "match": value})
    return hits


def detect_prompt_leakage(text: str, system_prompt: str | None = None) -> list[dict]:
    """
    Heuristic prompt-leakage detection: flags common leakage phrasing, and
    (if a system_prompt is provided) flags any 40+ character substring
    overlap between the model's output and the real system prompt --
    a strong signal the prompt itself was echoed back.
    """
    if not text:
        return []
    hits = []
    lowered = text.lower()
    for phrase in _LEAKAGE_PHRASES:
        if phrase in lowered:
            hits.append({"type": "leakage_phrase", "match": phrase})

    if system_prompt:
        window = 40
        sp_lower = system_prompt.lower()
        for i in range(0, max(len(sp_lower) - window, 0) + 1, window):
            chunk = sp_lower[i:i + window].strip()
            if len(chunk) >= window and chunk in lowered:
                hits.append({"type": "system_prompt_overlap", "match": chunk})
    return hits


def validate_json_schema(data: Any, schema: dict) -> tuple[bool, list[str]]:
    """Validates parsed LLM-generated JSON against a caller-supplied JSON Schema (draft 2020-12). Returns (is_valid, [error messages])."""
    validator = Draft202012Validator(schema)
    errors = [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in validator.iter_errors(data)]
    return (len(errors) == 0, errors)


def sanitize(text: str, system_prompt: str | None = None) -> dict:
    """Convenience wrapper running strip_xss + detect_pii + detect_prompt_leakage together."""
    return {
        "sanitized_text": strip_xss(text),
        "pii_hits": detect_pii(text),
        "prompt_leakage_hits": detect_prompt_leakage(text, system_prompt),
    }
