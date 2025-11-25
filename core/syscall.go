package core

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"

	"toxoglosser/utils"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	MEM_COMMIT_RESERVE     = MEM_COMMIT | MEM_RESERVE
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PROCESS_ALL_ACCESS     = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFF
)

// QueueUserAPC calls the Windows API - uses LazyDLL as this is a kernel32 function
// that has no direct syscall equivalent
func QueueUserAPC(pfnAPC uintptr, hThread windows.Handle, dwData uintptr) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procQueueUserAPC := kernel32.NewProc("QueueUserAPC")

	ret, _, _ := procQueueUserAPC.Call(
		pfnAPC,
		uintptr(hThread),
		dwData,
	)

	if ret == 0 {
		return syscall.GetLastError()
	}
	return nil
}