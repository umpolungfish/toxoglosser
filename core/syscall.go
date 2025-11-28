package core

import (
	"golang.org/x/sys/windows"
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
		return windows.GetLastError()
	}
	return nil
}