// core/manual_resolve.go
// Manual GetModuleHandle + GetProcAddress hashing implementation
// Replaces all LazyDLL/NewLazyDLL calls with manual API resolution

package core

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
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
	moduleHash := HashString(moduleName)
	
	// Get the PEB to enumerate loaded modules
	peb := getPEB()
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
		tableEntry := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(nextEntry)) - unsafe.Offsetof(LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks)))

		// Get the base DLL name and check if it matches
		if tableEntry.BaseDllName.Length > 0 {
			moduleNameStr := UTF16PtrToString((*uint16)(unsafe.Pointer(tableEntry.BaseDllName.Buffer)))
			if HashString(moduleNameStr) == moduleHash {
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
	funcHash := HashString(functionName)

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

	// Iterate through exported functions
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameAddr := *(*uint32)(unsafe.Pointer(namesArray + uintptr(i)*4))
		namePtr := unsafe.Pointer(modBase + uintptr(nameAddr))
		functionNameStr := ptrToString((*byte)(namePtr))

		if HashString(functionNameStr) == funcHash {
			ordinal := *(*uint16)(unsafe.Pointer(ordinalsArray + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(funcsArray + uintptr(ordinal)*4))
			funcAddr := modBase + uintptr(funcRVA)
			return funcAddr, nil
		}
	}

	return 0, syscall.Errno(0)
}

// HashString returns a djb2 hash of the string for API resolution
func HashString(s string) uint32 {
	var hash uint32 = 5381
	for i := 0; i < len(s); i++ {
		hash = ((hash << 5) + hash) + uint32(s[i])
	}
	return hash
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

// Helper functions and structures for manual resolution
type PEB_LDR_DATA struct {
	Length                     uint32
	Initialized                uint8
	_                          uint8 // padding
	InLoadOrderModuleIndex     uint16
	InMemoryOrderModuleIndex   uint16
	InInitializationOrderIndex uint16
	EntryInProgress            uintptr
	Spare                      uintptr
}

type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type LDR_DATA_TABLE_ENTRY struct {
	InMemoryOrderLinks        LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                   uintptr
	EntryPoint                uintptr
	SizeOfImage               uint32
	FullDllName               UNICODE_STRING
	BaseDllName               UNICODE_STRING
	_                         [8]byte // padding
	LoadCount                 uint16
	_                         uint16  // padding
	// ... other fields omitted for brevity
}

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

// getPEB retrieves the Process Environment Block
func getPEB() uintptr {
	return uintptr(*(*uintptr)(unsafe.Pointer(uintptr(*(*uintptr)(unsafe.Pointer(uintptr(0x60)))))))
}