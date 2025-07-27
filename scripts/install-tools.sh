#!/bin/bash
# Install security analysis tools for local development

set -e

echo "Installing security analysis tools..."

# Python tools
echo "Installing Python-based tools..."
pip install bandit safety pip-audit

# Semgrep
echo "Installing Semgrep..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install semgrep
else
    # Linux
    python3 -m pip install semgrep
fi

# TruffleHog
echo "Installing TruffleHog..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install trufflehog
else
    # Linux
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
fi

# OSV-Scanner
echo "Installing OSV-Scanner..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install osv-scanner
else
    # Linux
    curl -L https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /tmp/osv-scanner
    sudo mv /tmp/osv-scanner /usr/local/bin/osv-scanner
    sudo chmod +x /usr/local/bin/osv-scanner
fi

echo "Verifying installations..."
echo "Bandit version: $(bandit --version)"
echo "Safety version: $(safety --version)"
echo "Semgrep version: $(semgrep --version)"
echo "TruffleHog version: $(trufflehog --version)"
echo "OSV-Scanner version: $(osv-scanner --version)"

echo "All tools installed successfully!"