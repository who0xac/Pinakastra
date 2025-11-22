#!/bin/bash

# Pinakastra Installation Script for Linux/macOS
# Usage: sudo ./install.sh

set -e

echo "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→"
echo "                    Pinakastra Global Installation"
echo "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→"
echo

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}[✗]${NC} Go is not installed. Please install Go 1.21 or higher."
    exit 1
fi

echo -e "${GREEN}[✓]${NC} Go detected: $(go version)"
echo

# Build the binary
echo -e "${YELLOW}[+]${NC} Building Pinakastra..."
go build -o pinakastra -ldflags="-s -w" .

if [ $? -ne 0 ]; then
    echo -e "${RED}[✗]${NC} Build failed!"
    exit 1
fi

echo -e "${GREEN}[✓]${NC} Build successful"
echo

# Install to /usr/local/bin
echo -e "${YELLOW}[+]${NC} Installing to /usr/local/bin/pinakastra..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!]${NC} Installing requires sudo privileges..."
    sudo mv pinakastra /usr/local/bin/pinakastra
    sudo chmod +x /usr/local/bin/pinakastra
else
    mv pinakastra /usr/local/bin/pinakastra
    chmod +x /usr/local/bin/pinakastra
fi

if [ $? -ne 0 ]; then
    echo -e "${RED}[✗]${NC} Installation failed!"
    exit 1
fi

echo -e "${GREEN}[✓]${NC} Pinakastra installed to /usr/local/bin"
echo

# Create config directory
CONFIG_DIR="$HOME/.config/pinakastra"
if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}[+]${NC} Creating config directory at $CONFIG_DIR..."
    mkdir -p "$CONFIG_DIR"

    # Copy default config if exists
    if [ -f "configs/default.yaml" ]; then
        cp configs/default.yaml "$CONFIG_DIR/config.yaml"
        echo -e "${GREEN}[✓]${NC} Default config copied to $CONFIG_DIR/config.yaml"
    fi
fi

# Create results directory
RESULTS_DIR="$HOME/recon-results"
if [ ! -d "$RESULTS_DIR" ]; then
    echo -e "${YELLOW}[+]${NC} Creating results directory at $RESULTS_DIR..."
    mkdir -p "$RESULTS_DIR"
    echo -e "${GREEN}[✓]${NC} Results directory created"
fi

echo
echo "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→"
echo -e "${GREEN}[✓]${NC} Installation Complete!"
echo
echo -e "${CYAN}Installation Summary:${NC}"
echo -e "  ${CYAN}•${NC} Binary     : /usr/local/bin/pinakastra"
echo -e "  ${CYAN}•${NC} Config     : $CONFIG_DIR/config.yaml"
echo -e "  ${CYAN}•${NC} Results    : $RESULTS_DIR"
echo
echo -e "${CYAN}Usage:${NC}"
echo -e "  ${YELLOW}pinakastra -d example.com${NC}     - Start a scan"
echo -e "  ${YELLOW}pinakastra -c${NC}                 - Check installed tools"
echo -e "  ${YELLOW}pinakastra -h${NC}                 - Show help"
echo "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→"
echo

# Verify installation
if command -v pinakastra &> /dev/null; then
    echo -e "${GREEN}[✓]${NC} Verification: pinakastra command is available globally"
    echo
else
    echo -e "${RED}[✗]${NC} Verification failed. Please add /usr/local/bin to your PATH"
fi
