FROM python:3.11-slim

WORKDIR /app

# Set to "false" (--build-arg INSTALL_OPTIONAL_TOOLS=false) to skip the
# optional deeper-enrichment tools below and get a smaller/faster image.
# Every one of them is genuinely optional at runtime -- every service that
# calls out to an optional tool degrades gracefully (logs a warning, skips
# that one signal) if it isn't on PATH. Core functionality never depends on
# this arg. Each tool below is also individually fault-tolerant at build
# time (a stale release URL for one tool can't break the build for
# everyone else) -- consistent with the same graceful-degrade philosophy
# these tools have at runtime.
ARG INSTALL_OPTIONAL_TOOLS=true

# --- Core system packages -----------------------------------------------
# build-essential/libpq-dev: compiling psycopg2 and other C-extension deps
# curl: used throughout this file to fetch tool binaries
# dnsutils/nmap: Module 1 recon (dig, nmap)
# pango/cairo/gdk-pixbuf: WeasyPrint PDF report rendering (Module 5)
# unzip: needed to unpack jadx's release zip below
# default-jre-headless: apktool/jadx are JVM tools (MOB-1 deeper Android decompilation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl dnsutils nmap \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2 \
    unzip default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# --- Go toolchain + recon tools (Module 1) ------------------------------
# Every recon function degrades gracefully and logs a warning if its tool
# isn't found -- these aren't required to run the app, just to get real
# scan results instead of empty ones.
RUN curl -fsSL https://go.dev/dl/go1.21.5.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master
RUN nuclei -update-templates || true

# --- Optional deeper-enrichment tools (Expanded + Advanced Services) ----
# These are the tools documented in README.md's "Prerequisites" section as
# needing manual installation for Option B (local dev) -- installed here so
# the Docker path actually delivers on "Docker installs every tool for you."
# Each RUN below ends in `|| echo ...` rather than letting the step fail
# the build: a version bump or dead link for one optional tool should never
# block anyone from getting a working image.

# MOB-1 (Mobile App Security) — trufflehog: deeper secret scanning (Go binary)
RUN if [ "$INSTALL_OPTIONAL_TOOLS" = "true" ]; then \
      go install -v github.com/trufflesecurity/trufflehog/v3@latest \
        || echo "WARNING: trufflehog install failed, skipping (optional, MOB-1 degrades gracefully without it)" ; \
    fi

# DSO-4 (IaC Security Scanner) — kube-score / kubesec: deeper Kubernetes enrichment (Go binaries)
RUN if [ "$INSTALL_OPTIONAL_TOOLS" = "true" ]; then \
      go install -v github.com/zegl/kube-score/cmd/kube-score@latest \
        || echo "WARNING: kube-score install failed, skipping (optional, DSO-4 degrades gracefully without it)" ; \
      go install -v github.com/controlplaneio/kubesec/v2@latest \
        || echo "WARNING: kubesec install failed, skipping (optional, DSO-4 degrades gracefully without it)" ; \
    fi

# DSO-4 — hadolint: Dockerfile linting (static binary, no Go/JVM involved)
RUN if [ "$INSTALL_OPTIONAL_TOOLS" = "true" ]; then \
      ( curl -fsSL -o /usr/local/bin/hadolint \
          https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 \
        && chmod +x /usr/local/bin/hadolint ) \
        || echo "WARNING: hadolint install failed, skipping (optional, DSO-4 degrades gracefully without it)" ; \
    fi

# MOB-1 — apktool / jadx: deeper Android decompilation (JVM tools, need default-jre-headless above)
RUN if [ "$INSTALL_OPTIONAL_TOOLS" = "true" ]; then \
      ( curl -fsSL -o /usr/local/bin/apktool \
          https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
        && curl -fsSL -o /usr/local/bin/apktool.jar \
          https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar \
        && chmod +x /usr/local/bin/apktool ) \
        || echo "WARNING: apktool install failed, skipping (optional, MOB-1 degrades gracefully without it)" ; \
      ( curl -fsSL -o /tmp/jadx.zip \
          https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip \
        && unzip -q /tmp/jadx.zip -d /opt/jadx \
        && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
        && rm /tmp/jadx.zip ) \
        || echo "WARNING: jadx install failed, skipping (optional, MOB-1 degrades gracefully without it)" ; \
    fi

# WEB3-1 (Smart Contract Scanner) — mythril: deeper Solidity symbolic execution (pip, fetches its own solc versions at runtime)
RUN if [ "$INSTALL_OPTIONAL_TOOLS" = "true" ]; then \
      pip install --no-cache-dir mythril \
        || echo "WARNING: mythril install failed, skipping (optional, WEB3-1 degrades gracefully without it)" ; \
    fi

# IOT-1 (Hardware & IoT Security) — checksec: ELF binary hardening enrichment (single shell script)
RUN if [ "$INSTALL_OPTIONAL_TOOLS" = "true" ]; then \
      ( curl -fsSL -o /usr/local/bin/checksec \
          https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec \
        && chmod +x /usr/local/bin/checksec ) \
        || echo "WARNING: checksec install failed, skipping (optional, IOT-1 degrades gracefully without it)" ; \
    fi

# IOT-1 — real firmware extraction. The `binwalk` PyPI wheel (already pulled
# in via requirements.txt) ships an incomplete `binwalk.core` module and its
# console script fails at runtime -- app/services/firmware_analysis.py
# already degrades gracefully when that happens (falls back to scanning raw
# firmware bytes directly), but the Debian package is a genuinely working
# CLI, so install it and make sure it wins on PATH over the broken pip one.
RUN if [ "$INSTALL_OPTIONAL_TOOLS" = "true" ]; then \
      ( apt-get update \
        && apt-get install -y --no-install-recommends binwalk squashfs-tools cpio p7zip-full \
        && rm -rf /var/lib/apt/lists/* ) \
        || echo "WARNING: binwalk/extraction-tools install failed, skipping (optional, IOT-1 degrades gracefully without it)" ; \
    fi

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Re-point /usr/local/bin/binwalk (pip's broken console script, which sits
# earlier on PATH) at the real apt-installed binary -- must run after the
# pip install above, which is what creates the broken script in the first
# place. A no-op if the apt package above wasn't installed (INSTALL_OPTIONAL_TOOLS=false
# or that step failed) -- firmware_analysis.py degrades gracefully either way.
RUN if [ -x /usr/bin/binwalk ]; then ln -sf /usr/bin/binwalk /usr/local/bin/binwalk; fi

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
