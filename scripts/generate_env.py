#!/usr/bin/env python3
"""
First-run setup: create backend/.env with secure, randomly generated secrets.

The two secrets that MUST NOT use their insecure defaults in production are
SECRET_KEY (signs auth tokens) and ENCRYPTION_KEY (Fernet key that encrypts
stored third-party credentials). The app already refuses to start outside
development if these are unset/default -- this script generates real values
so a fresh install is secure by default instead of failing or, worse,
running on a guessable key.

Idempotent: if backend/.env already exists, existing values are preserved
(never overwrites a key you've already set, including API keys you added by
hand). Only missing keys get filled in.

Usage:
    python scripts/generate_env.py
"""
import os
import re
import secrets
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(ROOT, "backend", ".env")
EXAMPLE_PATH = os.path.join(ROOT, "backend", ".env.example")

# Values we generate rather than copy from the example's placeholder.
GENERATED = {
    "SECRET_KEY": lambda: secrets.token_urlsafe(48),
    "ENCRYPTION_KEY": lambda: _fernet_key(),
}

# In the Docker Compose network, services reach each other by service name,
# not localhost -- rewrite the example's localhost defaults so the container
# path works out of the box.
DOCKER_DEFAULTS = {
    "DATABASE_URL": "postgresql://track1:track1@db:5432/track1",
    "REDIS_URL": "redis://redis:6379/0",
    "CELERY_BROKER_URL": "redis://redis:6379/0",
    "CELERY_RESULT_BACKEND": "redis://redis:6379/1",
    "ENV": "production",
    "DEBUG": "false",
    # Same-origin: the browser talks to nginx (port 80), which proxies /api.
    # Good for local access out of the box; change this to your real portal
    # domain(s) to serve the platform to remote users (see the note printed
    # at the end of this script and the README quickstart).
    "ALLOWED_ORIGINS": "http://localhost",
}


def _fernet_key() -> str:
    try:
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode()
    except ImportError:
        # cryptography isn't installed in the host venv running this script
        # (it lives in the backend deps) -- fall back to an equivalent
        # 32-byte urlsafe-base64 key, which is exactly what Fernet produces.
        import base64
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def _parse_env(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


def main():
    if not os.path.exists(EXAMPLE_PATH):
        print(f"ERROR: {EXAMPLE_PATH} not found — run this from the repo root.")
        sys.exit(1)

    with open(EXAMPLE_PATH) as f:
        example_text = f.read()

    existing = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            existing = _parse_env(f.read())
        print(f"Found existing backend/.env — preserving {len(existing)} already-set value(s).")

    generated_count = 0
    docker_count = 0
    out_lines = []
    seen = set()
    for line in example_text.splitlines():
        m = re.match(r"^([A-Z0-9_]+)=(.*)$", line)
        if not m:
            out_lines.append(line)
            continue
        key, example_val = m.group(1), m.group(2)
        seen.add(key)

        if key in existing and existing[key] != "":
            out_lines.append(f"{key}={existing[key]}")
        elif key in GENERATED:
            out_lines.append(f"{key}={GENERATED[key]()}")
            generated_count += 1
        elif key in DOCKER_DEFAULTS:
            out_lines.append(f"{key}={DOCKER_DEFAULTS[key]}")
            docker_count += 1
        else:
            out_lines.append(line)

    with open(ENV_PATH, "w") as f:
        f.write("\n".join(out_lines) + "\n")

    print(f"Wrote {ENV_PATH}")
    print(f"  - generated {generated_count} secure secret(s) (SECRET_KEY, ENCRYPTION_KEY)")
    print(f"  - set {docker_count} Docker-network default(s) (DATABASE_URL, REDIS_URL, ...)")

    # Warn about the one key that isn't required to boot but that AI features
    # need -- so it's obvious up front, not after "no report generated".
    final = _parse_env("\n".join(out_lines))
    ai_key = final.get("ANTHROPIC_API_KEY", "")
    if not ai_key or ai_key in ("your-api-key-here", "test-key-for-local-verification"):
        print("\n  NOTE: ANTHROPIC_API_KEY is not set to a real key yet.")
        print("        Every non-AI feature works without it, but AI reports,")
        print("        executive summaries, and narratives will not generate")
        print("        until you set a real key in backend/.env.")

    print("\n  NOTE: to serve the portal to remote users (not just localhost),")
    print("        set ALLOWED_ORIGINS in backend/.env to your domain/IP, e.g.")
    print("        ALLOWED_ORIGINS=https://portal.youragency.com")


if __name__ == "__main__":
    main()
