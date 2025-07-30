#!/bin/bash
# Setup CodeQL for semantic code analysis

set -e

echo "Setting up CodeQL semantic code analysis engine..."

# CodeQL version
CODEQL_VERSION="2.16.1"

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PLATFORM="osx64"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    PLATFORM="linux64"
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Installation directory
INSTALL_DIR="$HOME/.codeql"
mkdir -p "$INSTALL_DIR"

# Download CodeQL CLI
echo "Downloading CodeQL CLI v${CODEQL_VERSION} for $OS..."
DOWNLOAD_URL="https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-${PLATFORM}.zip"

if command -v wget &> /dev/null; then
    wget -q --show-progress "$DOWNLOAD_URL" -O /tmp/codeql.zip
elif command -v curl &> /dev/null; then
    curl -L --progress-bar "$DOWNLOAD_URL" -o /tmp/codeql.zip
else
    echo "Neither wget nor curl is available. Please install one of them."
    exit 1
fi

# Extract CodeQL
echo "Extracting CodeQL..."
unzip -q /tmp/codeql.zip -d "$INSTALL_DIR"
rm /tmp/codeql.zip

# Make CodeQL executable
chmod +x "$INSTALL_DIR/codeql/codeql"

# Download CodeQL queries
echo "Downloading CodeQL query libraries..."
cd "$INSTALL_DIR"
if [ -d "codeql-repo" ]; then
    echo "Updating existing CodeQL queries..."
    cd codeql-repo
    git pull
else
    echo "Cloning CodeQL queries..."
    git clone --depth 1 https://github.com/github/codeql.git codeql-repo
fi

# Create directory for custom queries
echo "Creating custom queries directory..."
CUSTOM_QUERIES_DIR="rules/codeql"
mkdir -p "$CUSTOM_QUERIES_DIR"

# Install language support
echo "Setting up language support..."
cd "$INSTALL_DIR/codeql"

# Test installation
echo "Testing CodeQL installation..."
if "$INSTALL_DIR/codeql/codeql" version &> /dev/null; then
    echo "✓ CodeQL installed successfully!"
    "$INSTALL_DIR/codeql/codeql" version
else
    echo "✗ CodeQL installation failed"
    exit 1
fi

# Add to PATH
echo ""
echo "To add CodeQL to your PATH, add this line to your shell profile:"
echo "  export PATH=\"\$PATH:$INSTALL_DIR/codeql\""
echo ""

# Check if already in PATH
if ! command -v codeql &> /dev/null; then
    # Try to add to common shell profiles
    SHELL_PROFILE=""
    if [ -f "$HOME/.bashrc" ]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.zshrc" ]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [ -f "$HOME/.profile" ]; then
        SHELL_PROFILE="$HOME/.profile"
    fi

    if [ -n "$SHELL_PROFILE" ]; then
        echo "Adding CodeQL to PATH in $SHELL_PROFILE..."
        echo "" >> "$SHELL_PROFILE"
        echo "# CodeQL" >> "$SHELL_PROFILE"
        echo "export PATH=\"\$PATH:$INSTALL_DIR/codeql\"" >> "$SHELL_PROFILE"
        echo "Please run 'source $SHELL_PROFILE' or restart your terminal"
    fi
fi

# Install dependencies for different languages
echo ""
echo "Installing language-specific dependencies..."

if [[ "$OS" == "linux" ]]; then
    # Java support
    if ! command -v java &> /dev/null; then
        echo "Installing Java runtime for Java/Kotlin analysis..."
        sudo apt-get update && sudo apt-get install -y default-jre-headless
    fi

    # .NET support
    if ! command -v dotnet &> /dev/null; then
        echo "Installing .NET SDK for C# analysis..."
        wget https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh
        chmod +x /tmp/dotnet-install.sh
        /tmp/dotnet-install.sh --channel 8.0
        rm /tmp/dotnet-install.sh
    fi
elif [[ "$OS" == "macos" ]]; then
    if command -v brew &> /dev/null; then
        # Java support
        if ! command -v java &> /dev/null; then
            echo "Installing Java runtime for Java/Kotlin analysis..."
            brew install openjdk
        fi

        # .NET support
        if ! command -v dotnet &> /dev/null; then
            echo "Installing .NET SDK for C# analysis..."
            brew install --cask dotnet-sdk
        fi
    fi
fi

# Usage examples
echo ""
echo "CodeQL Usage Examples:"
echo ""
echo "1. Create a database for Python project:"
echo "   codeql database create mydb --language=python --source-root=/path/to/project"
echo ""
echo "2. Analyze with security queries:"
echo "   codeql database analyze mydb python-security-extended.qls --format=sarif-latest --output=results.sarif"
echo ""
echo "3. Create database for JavaScript/TypeScript:"
echo "   codeql database create jsdb --language=javascript --source-root=/path/to/project"
echo ""
echo "4. Run custom queries:"
echo "   codeql database analyze mydb rules/codeql/mcp_vulnerabilities.ql --format=csv --output=results.csv"
echo ""

# Docker instructions
echo "For Docker usage:"
echo "1. CodeQL is integrated into the scanner container"
echo "2. Custom queries can be added to $CUSTOM_QUERIES_DIR"
echo "3. Analysis runs automatically during security scans"
echo ""

# Performance tips
echo "Performance tips:"
echo "- Use --threads=0 to use all CPU cores"
echo "- Pre-compile databases for faster analysis"
echo "- Use query suites instead of individual queries"
echo "- Enable incremental analysis for large codebases"

echo ""
echo "Setup complete!"