# ---------- Base image (Debian bookworm) ----------
FROM python:3.11-slim-bookworm AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1

# Common OS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget ca-certificates gnupg lsb-release unzip xz-utils \
    build-essential pkg-config jq \
    && rm -rf /var/lib/apt/lists/*


# ---------- Builder stage (compile tools) ----------
FROM base AS builder

# Build toolchain + headers required by YARA
RUN apt-get update && apt-get install -y --no-install-recommends \
    automake autoconf libtool make gcc g++ \
    libssl-dev libjansson-dev libmagic-dev python3-dev \
    bison flex \
    && rm -rf /var/lib/apt/lists/*

# Python security tools (pin versions you want)
RUN pip install --no-cache-dir \
    bandit==1.7.10 \
    semgrep==1.127.0

# ---- Build and install YARA ----
ARG YARA_VERSION=4.5.4
RUN set -eux; \
    wget -qO /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz; \
    mkdir -p /tmp/yara && tar -xzf /tmp/yara.tar.gz -C /tmp/yara --strip-components=1; \
    cd /tmp/yara; \
    ./bootstrap.sh; \
    ./configure --enable-cuckoo --enable-magic --enable-dotnet; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig; \
    rm -rf /tmp/yara /tmp/yara.tar.gz

# yara-python matching the libyara above
RUN pip install --no-cache-dir yara-python==4.5.4

# Grype & Syft (installers place binaries in /usr/local/bin)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin

# TruffleHog
ARG TRUFFLEHOG_VERSION=3.90.2
RUN set -eux; \
    wget -q https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz; \
    tar -xzf trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz; \
    mv trufflehog /usr/local/bin/; \
    rm trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz; \
    chmod +x /usr/local/bin/trufflehog

# CodeQL CLI (amd64 only). On other architectures, install a stub that exits.
ARG CODEQL_VERSION=2.22.1
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ARCH" = "amd64" ]; then \
      wget -qO /tmp/codeql.zip https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip; \
      unzip -q /tmp/codeql.zip -d /opt; \
      mv /opt/codeql /opt/codeql-${CODEQL_VERSION}; \
      ln -s /opt/codeql-${CODEQL_VERSION} /opt/codeql; \
      rm /tmp/codeql.zip; \
    else \
      mkdir -p /opt/codeql; \
      printf '#!/bin/sh\necho "CodeQL CLI not available for %s"\nexit 1\n' "$ARCH" >/opt/codeql/codeql; \
      chmod +x /opt/codeql/codeql; \
    fi


# ---------- Final runtime image ----------
FROM base

# Minimal runtime deps: Java for some analyzers, file magic, tini as PID1
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless libjansson4 libmagic1 tini \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 LTS (for JS/TS autobuilds)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get update && apt-get install -y --no-install-recommends nodejs \
 && corepack enable \
 && corepack prepare yarn@stable --activate \
 && corepack prepare pnpm@latest --activate \
 && rm -rf /var/lib/apt/lists/*

# Go toolchain (1.22.x)
ARG GO_VERSION=1.22.5
RUN set -eux; \
    curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -o /tmp/go.tgz; \
    rm -rf /usr/local/go; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    ln -sf /usr/local/go/bin/go /usr/local/bin/go; \
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt; \
    rm /tmp/go.tgz

# Trivy (repository installed without deprecated apt-key)
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(. /etc/os-release && echo $VERSION_CODENAME) main" \
    > /etc/apt/sources.list.d/trivy.list \
 && apt-get update && apt-get install -y --no-install-recommends trivy \
 && rm -rf /var/lib/apt/lists/*

# Copy YARA (libs, headers, CLI) from builder
COPY --from=builder /usr/local/lib/libyara* /usr/local/lib/
COPY --from=builder /usr/local/include/yara* /usr/local/include/
COPY --from=builder /usr/local/bin/yara* /usr/local/bin/
RUN ldconfig

# Copy Python site-packages that contain security tooling (bandit, semgrep, yara-python)
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy security tool binaries from builder
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/
COPY --from=builder /usr/local/bin/grype /usr/local/bin/
COPY --from=builder /usr/local/bin/syft /usr/local/bin/

# Copy CodeQL CLI from builder
COPY --from=builder /opt/codeql /opt/codeql
ENV CODEQL_HOME=/opt/codeql
ENV PATH="/opt/codeql:${PATH}"

# App user & directories
RUN groupadd -r scanner && useradd -r -g scanner -m scanner \
 && mkdir -p /home/scanner/.cache /home/scanner/go /home/scanner/.codeql \
           /app/rules/yara /app/rules/codeql /tmp/mcp-scanner \
 && chown -R scanner:scanner /home/scanner /app /tmp/mcp-scanner

# Go env (cache to user dirs)
ENV GOPATH=/home/scanner/go \
    GOCACHE=/home/scanner/.cache/go-build \
    PATH=$PATH:/usr/local/go/bin:${GOPATH}/bin

WORKDIR /app

# (Optional) Copy rules so they are available in the image; safe if empty.
# If you maintain a local CodeQL pack for MCP rules here, it will be included.
COPY rules /app/rules

# Pre-warm CodeQL query packs (best effort). Also install local pack deps if present.
# This speeds up first scans and works even if rules are empty. Runs as root.
RUN if command -v codeql >/dev/null 2>&1; then \
      codeql pack download codeql/python-queries codeql/javascript-queries codeql/go-queries \
        --common-caches=/home/scanner/.codeql || true; \
      if [ -d /app/rules/codeql ]; then \
        codeql pack install /app/rules/codeql --common-caches=/home/scanner/.codeql || true; \
      fi; \
    fi \
 && chown -R scanner:scanner /home/scanner/.codeql

# Copy app requirements separately to leverage layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code last
COPY . .
RUN chown -R scanner:scanner /app

USER scanner

# App env
ENV PYTHONPATH=/app \
    LOG_LEVEL=INFO

# Healthcheck endpoint uses curl (present)
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use tini as PID 1 to handle signals and reap zombies
ENTRYPOINT ["/usr/bin/tini","--"]

# Run the API
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
