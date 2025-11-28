#!/bin/bash

# Proper build script for toxoglosser with Windows cross-compilation and advanced evasion techniques
# This script sets up the proper environment for building toxoglosser on Linux for Windows

echo "[*] Setting up proper build environment for Windows cross-compilation..."

# Ensure Go 1.20+ is used
export PATH=/usr/lib/go-1.20/bin:$PATH
go version

# Set required environment variables for cross-compilation
export CGO_ENABLED=1
export GOOS=windows
export GOARCH=amd64
export CC=x86_64-w64-mingw32-gcc

echo "[*] Environment variables set:"
echo "  - CGO_ENABLED=$CGO_ENABLED"
echo "  - GOOS=$GOOS"
echo "  - GOARCH=$GOARCH"
echo "  - CC=$CC"

# Check if Garble is installed
if ! command -v garble &> /dev/null; then
    echo "[-] Garble not found. Installing Garble..."
    go install mvdan.cc/garble@v0.9.3
    export GOBIN=$HOME/go/bin
    export PATH=$PATH:$GOBIN
fi

# Build options for size reduction and obfuscation
BUILD_LDFLAGS="-s -w"  # Strip debug symbols and other unnecessary data
BUILD_FLAGS="-trimpath" # Remove build path information

echo "[*] Building with LDFLAGS: $BUILD_LDFLAGS"

# Build the main executable with Garble and size optimizations
echo "[*] Building toxoglosser.exe with cross-compilation and obfuscation..."
if command -v garble &> /dev/null; then
    garble -tiny -literals -seed=random build -ldflags="$BUILD_LDFLAGS" $BUILD_FLAGS -o toxoglosser.exe toxoglosser.go
else
    echo "[-] Garble not found. Building with standard Go compiler..."
    go build -ldflags="$BUILD_LDFLAGS" $BUILD_FLAGS -o toxoglosser.exe toxoglosser.go
fi

if [ $? -eq 0 ]; then
    echo "[+] Successfully built toxoglosser.exe with cross-compilation"
    ls -la toxoglosser.exe
else
    echo "[-] Build failed, trying with verbose output..."
    if command -v garble &> /dev/null; then
        garble -debugdir=./debug -tiny -literals -seed=random build -ldflags="$BUILD_LDFLAGS" $BUILD_FLAGS -o toxoglosser.exe toxoglosser.go
    else
        go build -v -ldflags="$BUILD_LDFLAGS" $BUILD_FLAGS -o toxoglosser.exe toxoglosser.go
    fi
    exit 1
fi

# Optional: Compress with UPX if available (further reduces size and evades signatures)
if command -v upx &> /dev/null; then
    echo "[*] UPX found. Compressing binary..."
    upx --best --lzma toxoglosser.exe
    if [ $? -eq 0 ]; then
        echo "[+] Successfully compressed with UPX"
        ls -la toxoglosser.exe
    else
        echo "[-] UPX compression failed, but binary is still functional"
    fi
else
    echo "[-] UPX not found. Skipping compression (consider installing UPX for smaller size)"
fi

echo "[*] Build complete! Binary: toxoglosser.exe"