# Makefile for Toxoglosser (2025 Edition)
# Advanced process injection tool with modern evasion techniques

# Variables
BINARY_NAME=toxoglosser.exe
SOURCE_FILE=toxoglosser.go
GOOS=windows
GOARCH=amd64
CGO_ENABLED=1

# Compiler flags for size reduction and obfuscation
LDFLAGS=-ldflags="-s -w"
BUILD_FLAGS=-buildmode=pie -trimpath

# Check if Garble is available
HAS_GARBLE := $(shell command -v garble 2> /dev/null)

# Default target
.PHONY: all
all: build

# Build with Garble obfuscation (recommended)
.PHONY: build
build:
	@echo "[*] Building $(BINARY_NAME) with Garble obfuscation..."
	@if [ -n "$(HAS_GARBLE)" ]; then \
		garble -tiny -literals -seed=random build $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_NAME) $(SOURCE_FILE); \
		echo "[+] Successfully built $(BINARY_NAME) with Garble"; \
	else \
		echo "[-] Garble not found. Building with standard Go compiler..."; \
		go build $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_NAME) $(SOURCE_FILE); \
		echo "[+] Successfully built $(BINARY_NAME) with standard Go"; \
	fi
	@ls -la $(BINARY_NAME)

# Build without obfuscation (for debugging)
.PHONY: build-plain
build-plain:
	@echo "[*] Building $(BINARY_NAME) without obfuscation..."
	go build $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_NAME) $(SOURCE_FILE)
	@echo "[+] Successfully built $(BINARY_NAME) without obfuscation"

# Build with UPX compression
.PHONY: build-compressed
build-compressed: build
	@echo "[*] Compressing $(BINARY_NAME) with UPX..."
	@which upx > /dev/null && upx --best --lzma $(BINARY_NAME) || echo "[-] UPX not found. Skipping compression."
	@ls -la $(BINARY_NAME)

# Cross-compile from Linux to Windows
.PHONY: cross-build
cross-build:
	@echo "[*] Cross-compiling for Windows from Linux..."
	@export CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc && \
	if [ -n "$(HAS_GARBLE)" ]; then \
		GOOS=windows GOARCH=amd64 garble -tiny -literals -seed=random build $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_NAME) $(SOURCE_FILE); \
	else \
		GOOS=windows GOARCH=amd64 go build $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_NAME) $(SOURCE_FILE); \
	fi
	@echo "[+] Cross-compilation complete"

# Install Garble if not present
.PHONY: install-garble
install-garble:
	@echo "[*] Installing Garble..."
	go install mvdan.cc/garble@v0.9.3
	@echo "[+] Garble installed successfully"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "[*] Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@echo "[+] Clean complete"

# Show binary information
.PHONY: info
info:
	@echo "[*] Binary information for $(BINARY_NAME):"
	@test -f $(BINARY_NAME) && ls -la $(BINARY_NAME) || echo "[-] $(BINARY_NAME) not found"

# Show tool versions
.PHONY: version
version:
	@echo "[*] Tool versions:"
	@go version
	@which garble > /dev/null && garble version || echo "[-] Garble not installed"
	@which upx > /dev/null && upx --version | head -n 1 || echo "[-] UPX not installed"

# Help
.PHONY: help
help:
	@echo "Toxoglosser Build System"
	@echo "====================="
	@echo "make build            # Build with Garble obfuscation (recommended)"
	@echo "make build-plain      # Build without obfuscation"
	@echo "make build-compressed # Build and compress with UPX"
	@echo "make cross-build      # Cross-compile for Windows from Linux"
	@echo "make install-garble   # Install Garble obfuscator"
	@echo "make clean            # Remove build artifacts"
	@echo "make info             # Show binary information"
	@echo "make version          # Show tool versions"
	@echo "make help             # Show this help message"