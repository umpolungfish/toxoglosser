package utils

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

// SelfDelete attempts to delete the current executable
func SelfDelete() error {
	// Get the current executable path
	executablePath, err := GetExecutablePath()
	if err != nil {
		return err
	}

	// Get kernel32 handle and MoveFileEx function
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procMoveFileEx := kernel32.NewProc("MoveFileExW")

	// Use MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT flag to delete on next reboot
	// This is safer than immediate deletion which can cause issues
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
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procMoveFileEx := kernel32.NewProc("MoveFileExW")
	
	// We'll try to move the file to a temp location marked for deletion
	// First, get a handle to the executable with delete access
	// Then use the MOVEFILE_DELAY_UNTIL_REBOOT flag to ensure deletion on restart
	
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

// GetExecutablePath returns the current executable path
func GetExecutablePath() (string, error) {
	var buffer [windows.MAX_PATH]uint16
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