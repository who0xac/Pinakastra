#!/bin/bash

# Pinakastra Installation Script (Linux Only)
# Installs Pinakastra globally so you can run it from anywhere

set -e

echo "🔱 Pinakastra Installation Script"
echo "=================================="
echo "Platform: Linux"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go is not installed!${NC}"
    echo "Please install Go from: https://go.dev/dl/"
    exit 1
fi

echo -e "${GREEN}✅ Go is installed${NC}"
go version
echo ""

# Check if $GOPATH/bin is in PATH
GOBIN=$(go env GOBIN)
if [ -z "$GOBIN" ]; then
    GOBIN="$(go env GOPATH)/bin"
fi

if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo -e "${YELLOW}⚠️  Warning: $GOBIN is not in your PATH${NC}"
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo ""
    echo "  export PATH=\"\$PATH:$GOBIN\""
    echo ""
fi

# Build and install
echo "🔨 Building Pinakastra..."
go build -o pinakastra ./cmd/pinakastra

echo "📦 Installing to $GOBIN..."
go install ./cmd/pinakastra

echo ""
echo -e "${GREEN}✅ Installation complete!${NC}"
echo ""

# Create config directory
echo "📁 Setting up config directory..."
pinakastra version > /dev/null 2>&1 || true
echo -e "${GREEN}✅ Config directory created${NC}"
echo ""

# Check tools
echo "🔍 Checking required tools..."
pinakastra check

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎉 Pinakastra is now installed!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Usage:"
echo "  pinakastra -d target.com"
echo "  pinakastra check"
echo "  pinakastra --help"
echo ""
echo "Config directory:"
echo "  ~/.config/pinakastra/"
echo ""
