// utils/obfuscated_dll.go
// Contains functions for loading DLLs and procedures using obfuscated strings
package utils

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
	"toxoglosser/common"
)

// ObfuscatedLoadDLL loads a DLL using an obfuscated string
func ObfuscatedLoadDLL(obfuscated []byte) (*windows.LazyDLL, error) {
	dllName := DeobfuscateStringStatic(obfuscated)
	return windows.NewLazyDLL(dllName), nil
}

// HashBasedGetProcAddress gets a procedure by its hash instead of name
func HashBasedGetProcAddress(module windows.Handle, funcHash uint32) (uintptr, error) {
	// Get DOS/NT headers to parse exports
	modBase := uintptr(module)
	dosHeader := (*common.IMAGE_DOS_HEADER)(unsafe.Pointer(modBase))
	ntHeaders := (*common.IMAGE_NT_HEADERS64)(unsafe.Pointer(modBase + uintptr(dosHeader.E_lfanew)))

	// Get export directory
	exportDirAddr := ntHeaders.OptionalHeader.DataDirectory[common.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	if exportDirAddr == 0 {
		return 0, syscall.Errno(0)
	}

	exportDir := (*common.IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(modBase + uintptr(exportDirAddr)))

	// Get arrays of names, ordinals, and addresses
	namesArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfNames)))
	ordinalsArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfNameOrdinals)))
	funcsArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfFunctions)))

	// Iterate through exported functions
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameAddr := *(*uint32)(unsafe.Pointer(namesArray + uintptr(i)*4))
		namePtr := unsafe.Pointer(modBase + uintptr(nameAddr))
		functionNameStr := common.PtrToString((*byte)(namePtr))

		if common.HashString(functionNameStr) == funcHash {
			ordinal := *(*uint16)(unsafe.Pointer(ordinalsArray + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(funcsArray + uintptr(ordinal)*4))
			funcAddr := modBase + uintptr(funcRVA)
			return funcAddr, nil
		}
	}

	return 0, syscall.Errno(0)
}