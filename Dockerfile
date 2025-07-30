# Multi-stage build for efficiency
FROM python:3.11-slim-bullseye AS base

# Install base dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    ca-certificates \
    gnupg \
    lsb-release \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Builder stage for compiling tools
FROM base AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    automake \
    libtool \
    make \
    gcc \
    g++ \
    pkg-config \
    libssl-dev \
    libjansson-dev \
    libmagic-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip install --no-cache-dir \
    bandit==1.7.10 \
    semgrep==1.97.0

# Build and install YARA
RUN wget https://github.com/VirusTotal/yara/archive/v4.5.0.tar.gz && \
    tar -xzf v4.5.0.tar.gz && \
    cd yara-4.5.0 && \
    ./bootstrap.sh && \
    ./configure --enable-cuckoo --enable-magic --enable-dotnet && \
    make && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf yara-4.5.0 v4.5.0.tar.gz

# Now install yara-python (will link against the installed libyara)
RUN pip install --no-cache-dir yara-python==4.5.1

# Install other security tools
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy && \
    rm -rf /var/lib/apt/lists/*

# Install CodeQL - with architecture detection
ENV CODEQL_VERSION=2.15.5
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then \
        echo "Warning: CodeQL may have limited support on ARM architecture" && \
        echo "CodeQL will be skipped for ARM builds" && \
        mkdir -p /opt/codeql && \
        echo '#!/bin/sh\necho "CodeQL not available on ARM architecture"\nexit 1' > /opt/codeql/codeql && \
        chmod +x /opt/codeql/codeql; \
    else \
        cd /opt && \
        wget -q https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz && \
        tar -xzf codeql-bundle-linux64.tar.gz && \
        rm codeql-bundle-linux64.tar.gz && \
        chmod -R 755 /opt/codeql; \
    fi

# Install TruffleHog
RUN wget -q https://github.com/trufflesecurity/trufflehog/releases/download/v3.82.0/trufflehog_3.82.0_linux_amd64.tar.gz && \
    tar -xzf trufflehog_3.82.0_linux_amd64.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    rm trufflehog_3.82.0_linux_amd64.tar.gz && \
    chmod +x /usr/local/bin/trufflehog

# Final stage
FROM base

# Install runtime dependencies (removed clamdscan)
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    libssl1.1 \
    libjansson4 \
    libmagic1 \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Copy YARA libraries and binaries from builder
COPY --from=builder /usr/local/lib/libyara* /usr/local/lib/
COPY --from=builder /usr/local/include/yara* /usr/local/include/
COPY --from=builder /usr/local/bin/yara* /usr/local/bin/

# Update library cache
RUN ldconfig

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy security tools from builder
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/
COPY --from=builder /usr/local/bin/grype /usr/local/bin/
COPY --from=builder /usr/local/bin/syft /usr/local/bin/
COPY --from=builder /usr/bin/trivy /usr/bin/

# Copy CodeQL from builder
COPY --from=builder /opt/codeql /opt/codeql

# Set CodeQL in PATH
ENV PATH="/opt/codeql:${PATH}"
ENV CODEQL_HOME="/opt/codeql"

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner -m scanner

# Create necessary directories with proper permissions
RUN mkdir -p /home/scanner/.cache /app/rules/yara /app/rules/codeql /tmp/mcp-scanner && \
    chown -R scanner:scanner /home/scanner /app /tmp/mcp-scanner

WORKDIR /app

# Copy application requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Fix permissions after copying
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Set environment variables
ENV PYTHONPATH=/app
ENV LOG_LEVEL=INFO

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]