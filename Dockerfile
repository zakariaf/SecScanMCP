# Multi-stage build for smaller final image
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install security tools
RUN pip install --no-cache-dir \
    bandit==1.7.5 \
    safety==2.3.5 \
    pip-audit==2.6.1

# Install semgrep
RUN curl -L https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-linux-x64 -o /usr/local/bin/semgrep \
    && chmod +x /usr/local/bin/semgrep

# Install trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install osv-scanner
RUN curl -L https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy security tools from builder
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/semgrep
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner scanner

WORKDIR /app

# Copy application requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Change ownership
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]