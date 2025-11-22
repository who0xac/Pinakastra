# Pinakastra Makefile

.PHONY: help build install uninstall clean dev test run

# Variables
BINARY_NAME=pinakastra
INSTALL_PATH=/usr/local/bin
CONFIG_DIR=$(HOME)/.config/pinakastra
RESULTS_DIR=$(HOME)/recon-results

# Build flags
LDFLAGS=-ldflags="-s -w"

help: ## Show this help message
	@echo "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→"
	@echo "                         Pinakastra Makefile"
	@echo "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→"
	@echo ""
	@echo "Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

build: ## Build the binary
	@echo "[+] Building Pinakastra..."
	@go build $(LDFLAGS) -o $(BINARY_NAME) .
	@echo "[✓] Build complete: ./$(BINARY_NAME)"

install: build ## Build and install globally (requires sudo)
	@echo "[+] Installing to $(INSTALL_PATH)..."
	@sudo mv $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@sudo chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "[✓] Installed to $(INSTALL_PATH)/$(BINARY_NAME)"
	@mkdir -p $(CONFIG_DIR)
	@mkdir -p $(RESULTS_DIR)
	@if [ -f configs/default.yaml ]; then \
		cp configs/default.yaml $(CONFIG_DIR)/config.yaml 2>/dev/null || true; \
	fi
	@echo "[✓] Installation complete!"
	@echo ""
	@echo "Usage: $(BINARY_NAME) -d example.com"

uninstall: ## Uninstall Pinakastra
	@echo "[+] Uninstalling Pinakastra..."
	@sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "[✓] Uninstalled from $(INSTALL_PATH)"
	@echo "[!] Config and results directories preserved at:"
	@echo "    - $(CONFIG_DIR)"
	@echo "    - $(RESULTS_DIR)"

clean: ## Remove build artifacts
	@echo "[+] Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@echo "[✓] Clean complete"

dev: ## Build for development (with debug info)
	@echo "[+] Building for development..."
	@go build -o $(BINARY_NAME) .
	@echo "[✓] Development build complete"

test: ## Run tests
	@echo "[+] Running tests..."
	@go test -v ./...

run: build ## Build and run locally
	@echo "[+] Running Pinakastra..."
	@./$(BINARY_NAME)

check: ## Check installed recon tools
	@echo "[+] Checking installed tools..."
	@./$(BINARY_NAME) -c || go run . -c

# Cross-compilation targets
build-linux: ## Build for Linux
	@echo "[+] Building for Linux..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux .
	@echo "[✓] Built: $(BINARY_NAME)-linux"

build-windows: ## Build for Windows
	@echo "[+] Building for Windows..."
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME).exe .
	@echo "[✓] Built: $(BINARY_NAME).exe"

build-macos: ## Build for macOS
	@echo "[+] Building for macOS..."
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-macos .
	@echo "[✓] Built: $(BINARY_NAME)-macos"

build-all: build-linux build-windows build-macos ## Build for all platforms
	@echo "[✓] All platform builds complete"

deps: ## Download dependencies
	@echo "[+] Downloading dependencies..."
	@go mod download
	@go mod tidy
	@echo "[✓] Dependencies updated"

update: ## Update dependencies
	@echo "[+] Updating dependencies..."
	@go get -u ./...
	@go mod tidy
	@echo "[✓] Dependencies updated"

fmt: ## Format code
	@echo "[+] Formatting code..."
	@go fmt ./...
	@echo "[✓] Code formatted"

lint: ## Lint code
	@echo "[+] Linting code..."
	@golangci-lint run || echo "Install golangci-lint: https://golangci-lint.run/usage/install/"

.DEFAULT_GOAL := help
