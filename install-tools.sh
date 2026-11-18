#!/bin/bash
set -e

echo "Installing required security tools for STOscanner..."

# Install system dependencies
apt-get update
apt-get install -y --no-install-recommends \
    curl \
    autoconf \
    make \
    automake \
    libtool \
    pkg-config \
    golang \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Subfinder
echo "Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
cp /root/go/bin/subfinder /usr/local/bin/

# Install httpx
echo "Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
cp /root/go/bin/httpx /usr/local/bin/

# Install Nuclei
echo "Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
cp /root/go/bin/nuclei /usr/local/bin/

# Install Chaos
echo "Installing Chaos..."
# Clone and build chaos
git clone https://github.com/tiagorlampert/CHAOS /tmp/chaos
cd /tmp/chaos
# Build chaos binary
go build -o /usr/local/bin/chaos cmd/chaos/main.go
cd /
rm -rf /tmp/chaos

# Install Amass with libpostal dependencies
echo "Installing Amass dependencies..."
# First install libpostal
mkdir -p /tmp/libpostal
cd /tmp/libpostal
git clone https://github.com/openvenues/libpostal.git .
./bootstrap.sh
./configure --datadir=/usr/local/lib/libpostal
make -j$(nproc)
make install
ldconfig

# Install Amass
echo "Installing Amass..."
CGO_ENABLED=1 go install -v github.com/owasp-amass/amass/v5/cmd/amass@main
cp /root/go/bin/amass /usr/local/bin/

# Verify installations
echo "Verifying tool installations..."
subfinder --version 2>&1 | head -1
httpx --version 2>&1 | head -1
nuclei --version 2>&1 | head -1
chaos --help 2>&1 | head -1
amass --version 2>&1 | head -1

echo "All tools installed successfully!"