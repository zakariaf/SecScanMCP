#!/bin/bash
# Install security analysis tools for local development

set -e

echo "Installing security analysis tools..."

# Python tools
echo "Installing Python-based tools..."
pip install bandit semgrep

# Trivy
echo "Installing Trivy..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install aquasecurity/trivy/trivy
else
    # Linux
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt-get update
    sudo apt-get install -y trivy
fi

# Grype
echo "Installing Grype..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    brew tap anchore/grype
    brew install grype
else
    # Linux
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
fi

# Syft
echo "Installing Syft..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install syft
else
    # Linux
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
fi

# TruffleHog
echo "Installing TruffleHog..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install trufflehog
else
    # Linux
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
fi

echo "Verifying installations..."
echo "Bandit version: $(bandit --version)"
echo "Semgrep version: $(semgrep --version)"
echo "Trivy version: $(trivy --version)"
echo "Grype version: $(grype version)"
echo "Syft version: $(syft version)"
echo "TruffleHog version: $(trufflehog --version)"

echo "All tools installed successfully!"