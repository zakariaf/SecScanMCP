#!/bin/bash
# Setup ClamAV for local development and testing

set -e

echo "Setting up ClamAV malware detection engine..."

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

# Install ClamAV based on OS
echo "Installing ClamAV for $OS..."

if [[ "$OS" == "macos" ]]; then
    # macOS installation
    if ! command -v brew &> /dev/null; then
        echo "Homebrew is required. Please install it first."
        exit 1
    fi

    echo "Installing ClamAV via Homebrew..."
    brew install clamav

    # Setup directories
    sudo mkdir -p /usr/local/var/lib/clamav
    sudo mkdir -p /usr/local/var/log/clamav
    sudo chown -R $(whoami) /usr/local/var/lib/clamav
    sudo chown -R $(whoami) /usr/local/var/log/clamav

    # Copy config files
    cp /usr/local/etc/clamav/freshclam.conf.sample /usr/local/etc/clamav/freshclam.conf
    cp /usr/local/etc/clamav/clamd.conf.sample /usr/local/etc/clamav/clamd.conf

    # Configure ClamAV
    sed -i '' 's/^Example/#Example/' /usr/local/etc/clamav/freshclam.conf
    sed -i '' 's/^Example/#Example/' /usr/local/etc/clamav/clamd.conf

    # Enable TCP socket
    echo "TCPSocket 3310" >> /usr/local/etc/clamav/clamd.conf
    echo "TCPAddr 127.0.0.1" >> /usr/local/etc/clamav/clamd.conf

elif [[ "$OS" == "linux" ]]; then
    if [[ "$DISTRO" == "debian" ]]; then
        # Debian/Ubuntu installation
        echo "Installing ClamAV on Debian/Ubuntu..."
        sudo apt-get update
        sudo apt-get install -y clamav clamav-daemon clamav-freshclam

        # Stop services if running
        sudo systemctl stop clamav-freshclam || true
        sudo systemctl stop clamav-daemon || true

        # Configure ClamAV
        sudo sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf
        sudo sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf

        # Enable TCP socket
        sudo sed -i 's/^#TCPSocket 3310/TCPSocket 3310/' /etc/clamav/clamd.conf
        sudo sed -i 's/^#TCPAddr localhost/TCPAddr 0.0.0.0/' /etc/clamav/clamd.conf

        # Set proper permissions
        sudo chown -R clamav:clamav /var/lib/clamav

    elif [[ "$DISTRO" == "redhat" ]]; then
        # RHEL/CentOS/Fedora installation
        echo "Installing ClamAV on RHEL/CentOS/Fedora..."
        sudo yum install -y epel-release
        sudo yum install -y clamav clamav-update clamd

        # Configure ClamAV
        sudo sed -i 's/^Example/#Example/' /etc/freshclam.conf
        sudo sed -i 's/^Example/#Example/' /etc/clamd.conf

        # Enable TCP socket
        echo "TCPSocket 3310" | sudo tee -a /etc/clamd.conf
        echo "TCPAddr 0.0.0.0" | sudo tee -a /etc/clamd.conf
    fi
fi

# Update virus database
echo "Updating ClamAV virus database (this may take several minutes)..."
if [[ "$OS" == "macos" ]]; then
    freshclam
else
    sudo freshclam
fi

# Create systemd service for Linux
if [[ "$OS" == "linux" ]]; then
    echo "Creating systemd services..."

    # Create freshclam service
    sudo tee /etc/systemd/system/clamav-freshclam.service > /dev/null <<EOF
[Unit]
Description=ClamAV virus database updater
Documentation=man:freshclam(1) man:freshclam.conf(5) https://www.clamav.net/documents
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/bin/freshclam -d --foreground=false
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # Create clamd service
    sudo tee /etc/systemd/system/clamav-daemon.service > /dev/null <<EOF
[Unit]
Description=ClamAV daemon
Documentation=man:clamd(8) man:clamd.conf(5) https://www.clamav.net/documents
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/clamd --foreground=false
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and start services
    sudo systemctl daemon-reload
    sudo systemctl enable clamav-freshclam clamav-daemon
    sudo systemctl start clamav-freshclam
    sudo systemctl start clamav-daemon
fi

# Test ClamAV installation
echo "Testing ClamAV installation..."
sleep 5  # Give services time to start

# Create EICAR test file
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
echo "$EICAR" > /tmp/eicar.txt

# Test with clamdscan
if command -v clamdscan &> /dev/null; then
    echo "Testing with clamdscan..."
    if clamdscan /tmp/eicar.txt 2>/dev/null | grep -q "FOUND"; then
        echo "✓ ClamAV is working correctly!"
    else
        echo "✗ ClamAV test failed. Please check the installation."
    fi
else
    echo "clamdscan not found. Testing with clamscan..."
    if clamscan /tmp/eicar.txt 2>/dev/null | grep -q "FOUND"; then
        echo "✓ ClamAV is working correctly!"
    else
        echo "✗ ClamAV test failed. Please check the installation."
    fi
fi

# Clean up test file
rm -f /tmp/eicar.txt

# Display version information
echo ""
echo "ClamAV installation completed!"
echo "Version information:"
clamscan --version

# Docker instructions
echo ""
echo "For Docker usage:"
echo "1. Use the official ClamAV image: docker pull clamav/clamav:latest"
echo "2. Or use docker-compose with the provided configuration"
echo "3. ClamAV will be available on port 3310"

# Configuration tips
echo ""
echo "Configuration tips:"
echo "- ClamAV is configured to listen on TCP port 3310"
echo "- Virus database updates run automatically"
echo "- Logs are available in /var/log/clamav/ (Linux) or /usr/local/var/log/clamav/ (macOS)"
echo "- To manually update virus database: freshclam"
echo "- To scan a file: clamdscan /path/to/file"
echo "- To scan a directory: clamdscan -r /path/to/directory"

echo ""
echo "Setup complete!"