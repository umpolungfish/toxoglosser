// core/manual_resolve.go
// Manual GetModuleHandle + GetProcAddress hashing implementation
// Replaces all LazyDLL/NewLazyDLL calls with manual API resolution

package core

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
	"toxoglosser/common"
)

// FunctionHash represents a hash of a function name
type FunctionHash struct {
	ModuleName string
	FuncName   string
	Hash       uint32
}

// ManualGetProcAddress resolves a function address by hashing the function name
func ManualGetProcAddress(moduleName string, functionName string) (uintptr, error) {
	// Get the module handle by name using a hash-based approach
	moduleHandle, err := GetModuleHandleByHash(moduleName)
	if err != nil {
		return 0, err
	}

	// Get the function address by hashing the function name
	addr, err := GetProcAddressByHash(windows.Handle(moduleHandle), functionName)
	if err != nil {
		return 0, err
	}

	return addr, nil
}

// GetModuleHandleByHash gets a module handle by hashing the module name
func GetModuleHandleByHash(moduleName string) (uintptr, error) {
	// Use a hash to avoid direct string usage
	moduleHash := common.HashString(moduleName)

	// Get the PEB to enumerate loaded modules
	peb := common.GetPEB()
	if peb == 0 {
		return 0, syscall.Errno(1)
	}

	// Get the loader list from the PEB
	loaderData := (*PEB_LDR_DATA)(unsafe.Pointer(peb + 0x18))
	inMemoryOrderModuleList := uintptr(unsafe.Pointer(&loaderData.InMemoryOrderModuleList))

	// Iterate through the loaded modules
	currentEntry := (*LIST_ENTRY)(unsafe.Pointer(inMemoryOrderModuleList))
	nextEntry := (*LIST_ENTRY)(unsafe.Pointer(currentEntry.Flink))

	for nextEntry != (*LIST_ENTRY)(unsafe.Pointer(inMemoryOrderModuleList)) {
		// Get the LDR_DATA_TABLE_ENTRY
		tableEntry := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(nextEntry))

		// Get the base DLL name and check if it matches
		if tableEntry.BaseDllName.Length > 0 {
			moduleNameStr := UTF16PtrToString((*uint16)(unsafe.Pointer(tableEntry.BaseDllName.Buffer)))
			if common.HashString(moduleNameStr) == moduleHash {
				return uintptr(tableEntry.DllBase), nil
			}
		}

		// Move to the next entry
		nextEntry = (*LIST_ENTRY)(unsafe.Pointer(nextEntry.Flink))
	}

	return 0, syscall.Errno(1)
}

// GetProcAddressByHash finds a function address by hashing the function name
func GetProcAddressByHash(module windows.Handle, functionName string) (uintptr, error) {
	// Calculate the hash of the function name
	funcHash := common.HashString(functionName)

	// Get the module base address and DOS/NT headers to parse exports
	modBase := uintptr(module)
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(modBase))
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(modBase + uintptr(dosHeader.E_lfanew)))

	// Get export directory
	exportDirAddr := ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress
	if exportDirAddr == 0 {
		return 0, syscall.Errno(0)
	}

	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(modBase + uintptr(exportDirAddr)))

	// Get arrays of names, ordinals, and addresses
	namesArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfNames)))
	ordinalsArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfNameOrdinals)))
	funcsArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfFunctions)))

	// Iterate through exported functions
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameAddr := *(*uint32)(unsafe.Pointer(namesArray + uintptr(i)*4))
		namePtr := unsafe.Pointer(modBase + uintptr(nameAddr))
		functionNameStr := ptrToString((*byte)(namePtr))

		if common.HashString(functionNameStr) == funcHash {
			ordinal := *(*uint16)(unsafe.Pointer(ordinalsArray + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(funcsArray + uintptr(ordinal)*4))
			funcAddr := modBase + uintptr(funcRVA)
			return funcAddr, nil
		}
	}

	return 0, syscall.Errno(0)
}

// ptrToString converts a C string pointer to a Go string
func ptrToString(ptr *byte) string {
	if ptr == nil {
		return ""
	}

	p := (*[1 << 30]byte)(unsafe.Pointer(ptr))
	for i := 0; i < len(p); i++ {
		if p[i] == 0 {
			return string(p[:i])
		}
	}
	return string(p[:])
}

// UTF16PtrToString converts a UTF-16 pointer to a Go string
func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}

	// Find the length of the string by looking for null terminator
	n := 0
	for ptr := p; *ptr != 0; ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) {
		n++
	}

	// Convert to []uint16 slice
	slice := (*[1 << 28]uint16)(unsafe.Pointer(p))[:n:n]
	return syscall.UTF16ToString(slice)
}

