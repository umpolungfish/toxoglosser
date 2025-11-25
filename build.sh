#!/bin/bash

# Build script for toxoglosser with Garble obfuscation and size reduction (2025 edition)
# This script builds the toxoglosser binary with advanced obfuscation and size optimization

echo "[*] Building toxoglosser with Garble obfuscation and size reduction..."

# Check if Garble is installed
if ! command -v garble &> /dev/null; then
    echo "[-] Garble not found. Installing Garble..."
    go install mvdan.cc/garble@latest
    export GOBIN=$HOME/go/bin
    export PATH=$PATH:$GOBIN
fi

# Build options for size reduction
BUILD_TAGS=""
BUILD_LDFLAGS="-s -w"  # Strip debug symbols and other unnecessary data
BUILD_FLAGS="-trimpath" # Remove build path information

echo "[*] Building with LDFLAGS: $BUILD_LDFLAGS"

# Build the main executable with Garble and size optimizations
echo "[*] Building toxoglosser.exe with obfuscation..."
garble -tiny -literals -seed=random build -ldflags="$BUILD_LDFLAGS" -tags="$BUILD_TAGS" $BUILD_FLAGS -o toxoglosser.exe toxoglosser.go

if [ $? -eq 0 ]; then
    echo "[+] Successfully built toxoglosser.exe with Garble obfuscation"
    ls -la toxoglosser.exe
else
    echo "[-] Build failed"
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