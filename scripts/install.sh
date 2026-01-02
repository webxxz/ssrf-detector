#!/bin/bash

# SSRF Detector Installation Script

set -e

echo "=== SSRF Detector Installation ==="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

print_status "Detected OS: $OS $ARCH"

# Check Go installation
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go 1.21 or later."
    echo "Visit: https://golang.org/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
print_status "Go version: $GO_VERSION"

# Check minimum Go version
MIN_VERSION="1.21"
if [ "$(printf '%s\n' "$MIN_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]; then
    print_error "Go version 1.21 or later required"
    exit 1
fi

# Install directory
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

print_status "Installation directory: $INSTALL_DIR"

# Build the binary
print_status "Building SSRF Detector..."
go build -o ssrfdetect -ldflags="-s -w" cmd/ssrfdetect/main.go

# Install binary
print_status "Installing binary to $INSTALL_DIR..."
mv ssrfdetect "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/ssrfdetect"

# Check if install dir is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "⚠️  $INSTALL_DIR is not in your PATH"
    echo ""
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
    echo ""
fi

# Create config directory
CONFIG_DIR="$HOME/.config/ssrfdetect"
mkdir -p "$CONFIG_DIR"

# Copy example config if exists
if [ -f "configs/config.yaml.example" ]; then
    cp configs/config.yaml.example "$CONFIG_DIR/config.yaml.example"
    print_status "Example config copied to $CONFIG_DIR"
fi

# Verify installation
if command -v ssrfdetect &> /dev/null; then
    VERSION=$(ssrfdetect --version 2>&1 | head -1)
    print_status "Installation successful!"
    echo ""
    echo "  $VERSION"
    echo "  Binary: $INSTALL_DIR/ssrfdetect"
    echo ""
else
    print_status "Binary installed to: $INSTALL_DIR/ssrfdetect"
    echo ""
    echo "Run with: $INSTALL_DIR/ssrfdetect"
    echo ""
fi

# Usage hint
echo "=== Quick Start ==="
echo ""
echo "1. Setup OOB domain (required):"
echo "   ./scripts/setup_oob_server.sh"
echo ""
echo "2. Run basic scan:"
echo "   ssrfdetect -u 'https://example.com/fetch?url=test' \\"
echo "              -p url \\"
echo "              --oob-domain your-oob-domain.com \\"
echo "              -v"
echo ""
echo "3. Documentation:"
echo "   ssrfdetect --help"
echo "   cat docs/USAGE_GUIDE.md"
echo ""

print_status "Installation complete!"