package utils

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

// HashAPI resolves API functions by hash instead of name
func HashAPI(moduleName string, functionName string) (uintptr, error) {
	// For now, we'll use the LazyDLL approach as a fallback since the direct approach
	// requires more complex handling that may not be available in cross-compilation
	// This is a placeholder that should be replaced with true API hashing in production
	hModule := windows.NewLazyDLL(moduleName)
	hModHandle := windows.Handle(hModule.Handle())

	if hModHandle == 0 {
		return 0, syscall.Errno(0)
	}

	return getProcAddressByHashForModule(uintptr(hModHandle), functionName)
}

// getProcAddressByHashForModule finds a function address by its hashed name in a module
func getProcAddressByHashForModule(modBase uintptr, functionName string) (uintptr, error) {
	// Get DOS/NT headers to parse exports
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(modBase))
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(modBase + uintptr(dosHeader.E_lfanew)))

	// Get export directory
	exportDirAddr := ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	if exportDirAddr == 0 {
		return 0, syscall.Errno(0)
	}

	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(modBase + uintptr(exportDirAddr)))

	// Get arrays of names, ordinals, and addresses
	namesArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfNames)))
	ordinalsArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfNameOrdinals)))
	funcsArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfFunctions)))

	// Calculate hash of function name
	targetHash := HashString(functionName)

	// Iterate through exported functions
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameAddr := *(*uint32)(unsafe.Pointer(namesArray + uintptr(i)*4))
		namePtr := unsafe.Pointer(modBase + uintptr(nameAddr))
		functionNameStr := ptrToString((*byte)(namePtr))

		if HashString(functionNameStr) == targetHash {
			ordinal := *(*uint16)(unsafe.Pointer(ordinalsArray + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(funcsArray + uintptr(ordinal)*4))
			funcAddr := modBase + uintptr(funcRVA)
			return funcAddr, nil
		}
	}

	return 0, syscall.Errno(0)
}

// GetProcAddressByHash finds a function address by its hashed name in a module
func GetProcAddressByHash(module windows.Handle, functionName string) (uintptr, error) {
	// Get the module base address and DOS/NT headers to parse exports
	modBase := uintptr(module)
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(modBase))
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(modBase + uintptr(dosHeader.E_lfanew)))

	// Get export directory
	exportDirAddr := ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	if exportDirAddr == 0 {
		return 0, syscall.Errno(0)
	}

	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(modBase + uintptr(exportDirAddr)))

	// Get arrays of names, ordinals, and addresses
	namesArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfNames)))
	ordinalsArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfNameOrdinals)))
	funcsArray := uintptr(unsafe.Pointer(modBase + uintptr(exportDir.AddressOfFunctions)))

	// Calculate hash of function name
	targetHash := HashString(functionName)

	// Iterate through exported functions
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameAddr := *(*uint32)(unsafe.Pointer(namesArray + uintptr(i)*4))
		namePtr := unsafe.Pointer(modBase + uintptr(nameAddr))
		functionNameStr := ptrToString((*byte)(namePtr))

		if HashString(functionNameStr) == targetHash {
			ordinal := *(*uint16)(unsafe.Pointer(ordinalsArray + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(funcsArray + uintptr(ordinal)*4))
			funcAddr := modBase + uintptr(funcRVA)
			return funcAddr, nil
		}
	}

	return 0, syscall.Errno(0)
}


// Helper functions and structures for API hashing
type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

const IMAGE_DIRECTORY_ENTRY_EXPORT = 0

// Helper function to convert a C string to Go string
func ptrToString(ptr *byte) string {
	if ptr == nil {
		return ""
	}

	p := (*[10000]byte)(unsafe.Pointer(ptr))
	for i := 0; i < len(p); i++ {
		if p[i] == 0 {
			return string(p[:i])
		}
	}
	return string(p[:])
}