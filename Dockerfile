# Multi-stage build for smaller final image
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip install --no-cache-dir \
    bandit==1.7.10 \
    semgrep==1.97.0

# Install Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy && \
    rm -rf /var/lib/apt/lists/*

# Install Grype (specific version to avoid GitHub API issues)
RUN wget https://github.com/anchore/grype/releases/download/v0.84.0/grype_0.84.0_linux_amd64.tar.gz && \
    tar -xzf grype_0.84.0_linux_amd64.tar.gz && \
    mv grype /usr/local/bin/ && \
    rm grype_0.84.0_linux_amd64.tar.gz

# Install Syft (specific version)
RUN wget https://github.com/anchore/syft/releases/download/v1.18.0/syft_1.18.0_linux_amd64.tar.gz && \
    tar -xzf syft_1.18.0_linux_amd64.tar.gz && \
    mv syft /usr/local/bin/ && \
    rm syft_1.18.0_linux_amd64.tar.gz

# Install TruffleHog (specific version)
RUN wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.82.0/trufflehog_3.82.0_linux_amd64.tar.gz && \
    tar -xzf trufflehog_3.82.0_linux_amd64.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    rm trufflehog_3.82.0_linux_amd64.tar.gz

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    docker.io \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy security tools from builder
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/semgrep
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /usr/bin/trivy /usr/bin/trivy
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner scanner

WORKDIR /app

# Copy application requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create cache directories with proper permissions BEFORE switching to scanner user
RUN mkdir -p /home/scanner/.cache/trivy && \
    mkdir -p /home/scanner/.cache/grype && \
    mkdir -p /home/scanner/.cache/syft && \
    mkdir -p /tmp/mcp-scanner && \
    chown -R scanner:scanner /home/scanner && \
    chown -R scanner:scanner /tmp/mcp-scanner && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Set environment variables for cache directories
ENV TRIVY_CACHE_DIR=/home/scanner/.cache/trivy
ENV GRYPE_DB_CACHE_DIR=/home/scanner/.cache/grype
ENV SYFT_CACHE_DIR=/home/scanner/.cache/syft

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]