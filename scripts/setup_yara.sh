#!/bin/bash
# scripts/setup_yara.sh
# Setup YARA for advanced pattern matching

set -e

echo "Setting up YARA pattern matching engine..."

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    # Detect distribution
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
    else
        DISTRO="unknown"
    fi
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Install YARA based on OS
echo "Installing YARA for $OS..."

if [[ "$OS" == "macos" ]]; then
    # macOS installation
    if ! command -v brew &> /dev/null; then
        echo "Homebrew is required. Please install it first."
        exit 1
    fi

    echo "Installing YARA via Homebrew..."
    brew install yara

    # Install Python bindings
    pip3 install yara-python

elif [[ "$OS" == "linux" ]]; then
    if [[ "$DISTRO" == "debian" ]]; then
        # Debian/Ubuntu installation
        echo "Installing YARA on Debian/Ubuntu..."

        # Install dependencies
        sudo apt-get update
        sudo apt-get install -y \
            automake \
            libtool \
            make \
            gcc \
            autoconf \
            pkg-config \
            libssl-dev \
            libjansson-dev \
            libmagic-dev \
            python3-dev \
            python3-pip

        # Download and compile YARA
        YARA_VERSION="4.5.0"
        wget https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz
        tar -xzf v${YARA_VERSION}.tar.gz
        cd yara-${YARA_VERSION}

        # Build YARA
        ./bootstrap.sh
        ./configure --enable-cuckoo --enable-magic --enable-dotnet
        make
        sudo make install

        # Update library path
        sudo ldconfig

        # Install Python bindings
        pip3 install yara-python

        # Cleanup
        cd ..
        rm -rf yara-${YARA_VERSION} v${YARA_VERSION}.tar.gz

    elif [[ "$DISTRO" == "redhat" ]]; then
        # RHEL/CentOS/Fedora installation
        echo "Installing YARA on RHEL/CentOS/Fedora..."

        # Install dependencies
        sudo yum install -y \
            automake \
            libtool \
            make \
            gcc \
            autoconf \
            pkgconfig \
            openssl-devel \
            jansson-devel \
            file-devel \
            python3-devel \
            python3-pip

        # Download and compile YARA
        YARA_VERSION="4.5.0"
        wget https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz
        tar -xzf v${YARA_VERSION}.tar.gz
        cd yara-${YARA_VERSION}

        # Build YARA
        ./bootstrap.sh
        ./configure --enable-cuckoo --enable-magic --enable-dotnet
        make
        sudo make install

        # Update library path
        sudo ldconfig

        # Install Python bindings
        pip3 install yara-python

        # Cleanup
        cd ..
        rm -rf yara-${YARA_VERSION} v${YARA_VERSION}.tar.gz
    fi
fi

# Create YARA rules directory structure
echo "Creating YARA rules directory structure..."
RULES_DIR="rules/yara"
mkdir -p "$RULES_DIR"

# Download community YARA rules
echo "Downloading community YARA rules..."

# Awesome YARA collection
git clone https://github.com/InQuest/awesome-yara.git /tmp/awesome-yara 2>/dev/null || true

# Yara-Rules repository
git clone https://github.com/Yara-Rules/rules.git /tmp/yara-rules 2>/dev/null || true

# Copy useful rules
if [ -d "/tmp/yara-rules" ]; then
    echo "Installing community rules..."
    cp /tmp/yara-rules/malware/*.yar "$RULES_DIR/" 2>/dev/null || true
    cp /tmp/yara-rules/cve_rules/*.yar "$RULES_DIR/" 2>/dev/null || true
fi

# Clean up
rm -rf /tmp/awesome-yara /tmp/yara-rules

# Test YARA installation
echo "Testing YARA installation..."

# Create test rule
cat > /tmp/test.yar << 'EOF'
rule test_rule {
    strings:
        $test = "test"
    condition:
        $test
}
EOF

# Create test file
echo "test" > /tmp/test.txt

# Run test
if yara /tmp/test.yar /tmp/test.txt 2>/dev/null | grep -q "test_rule"; then
    echo "✓ YARA is working correctly!"
else
    echo "✗ YARA test failed. Please check the installation."
fi

# Clean up test files
rm -f /tmp/test.yar /tmp/test.txt

# Test Python integration
echo "Testing YARA Python integration..."
python3 -c "
import yara
rule = yara.compile(source='rule test { condition: true }')
matches = rule.match(data=b'test')
print('✓ YARA Python integration is working!' if matches else '✗ Python integration failed')
"

# Display version information
echo ""
echo "YARA installation completed!"
echo "Version information:"
yara --version

# Configuration tips
echo ""
echo "Configuration tips:"
echo "- YARA rules are stored in: $RULES_DIR"
echo "- To compile rules: yara -c rules.yar"
echo "- To scan files: yara rules.yar target_file"
echo "- To scan directories: yara -r rules.yar target_directory"
echo "- To output JSON: yara -j rules.yar target"

# Performance tips
echo ""
echo "Performance optimization:"
echo "- Use compiled rules for better performance: yarac rules.yar compiled.yarc"
echo "- Scan with compiled rules: yara compiled.yarc target"
echo "- Use -p flag for faster scanning (skip files based on extension)"
echo "- Use -f flag for fast matching mode"

# Docker instructions
echo ""
echo "For Docker usage:"
echo "1. YARA is integrated into the scanner container"
echo "2. Rules are automatically loaded from $RULES_DIR"
echo "3. Custom rules can be added to the rules directory"

echo ""
echo "Setup complete!"