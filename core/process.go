package core

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

var (
	procKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	procCreateToolhelp32SnapshotLocal = procKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstLocal          = procKernel32.NewProc("Process32First")
	procProcess32NextLocal           = procKernel32.NewProc("Process32Next")
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
)

// PROCESSENTRY32 structure for process enumeration
type PROCESSENTRY32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// GetProcessIdByName finds the PID of a process by its name
func GetProcessIdByName(processName string) uint32 {
	snapshot, _, _ := procCreateToolhelp32SnapshotLocal.Call(
		TH32CS_SNAPPROCESS,
		0,
	)

	if snapshot == uintptr(windows.InvalidHandle) {
		return 0
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	ret, _, _ := procProcess32FirstLocal.Call(
		snapshot,
		uintptr(unsafe.Pointer(&pe32)),
	)

	if ret == 0 {
		return 0
	}

	for {
		// Convert the unused variable issue in syscall.go
		name := windows.UTF16ToString(pe32.ExeFile[:])

		if name == processName {
			return pe32.ProcessID
		}

		ret, _, _ := procProcess32NextLocal.Call(
			snapshot,
			uintptr(unsafe.Pointer(&pe32)),
		)

		if ret == 0 {
			break
		}
	}

	return 0
}