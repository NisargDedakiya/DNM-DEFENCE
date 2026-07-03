# llm-output-sanitizer

A small, dependency-light Python library for sanitizing and validating
LLM output before it's used somewhere that trusts it too much: rendered
into a browser, written to a database, piped into a shell, or returned
from an API. Built to address OWASP LLM Top 10's **LLM02: Insecure
Output Handling** and **LLM06: Sensitive Information Disclosure**.

This package is standalone on purpose — it has no dependency on the
Track 1 platform and can be installed and used in any Python project.

## Install

```bash
pip install -e packages/llm-output-sanitizer   # local editable install
# or, once published:
pip install llm-output-sanitizer
```

For the optional Claude-based semantic PII layer:

```bash
pip install -e "packages/llm-output-sanitizer[semantic]"
```

> **Note:** this package is built and tested in this repository but is
> **not yet published to PyPI** — that requires the project owner's own
> PyPI account/credentials, which is a real-world action outside what
> this codebase can do on its own. Publishing is a documented follow-up.

## Usage

```python
from llm_output_sanitizer import sanitize

result = sanitize(llm_response_text)
result["sanitized_text"]      # XSS-stripped text, safe to render as HTML
result["pii_hits"]            # [{"type": "email", "match": "..."}, ...]
result["prompt_leakage_hits"] # phrases suggesting the system prompt leaked
```

Individual functions are also exposed directly:

```python
from llm_output_sanitizer import strip_xss, detect_pii, detect_prompt_leakage, validate_json_schema

clean = strip_xss("<script>alert(1)</script>Hello")  # "Hello"
hits = detect_pii("Contact me at jane@example.com")   # [{"type": "email", "match": "jane@example.com"}]
leaks = detect_prompt_leakage(model_output, system_prompt="You are a helpful support bot for Acme.")
is_valid, errors = validate_json_schema(parsed_json, my_schema)
```

## What it does NOT do

- It does not call out to any LLM by default (the semantic PII layer is
  opt-in and requires `ANTHROPIC_API_KEY` to be passed explicitly by the
  caller — this package never reads environment variables on its own).
- It does not guarantee 100% PII recall — the regex patterns cover common
  formats (email, phone, a few national ID formats) as a first line of
  defense, not a certified PII-detection engine.
- It does not replace input validation on the LLM's *prompt* side (see
  the platform's separate Prompt Injection Testing Suite for that).
