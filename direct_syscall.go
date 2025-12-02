// Package core includes direct syscall implementations using Tartarus' Gate technique for true direct syscalls
package core

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

// NtAllocateVirtualMemoryDirect makes a direct syscall to NtAllocateVirtualMemory using Tartarus' Gate
func NtAllocateVirtualMemoryDirect(processHandle windows.Handle, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint32, protect uint32) error {
	return NtAllocateVirtualMemory(processHandle, baseAddress, zeroBits, regionSize, allocationType, protect)
}

// NtWriteVirtualMemoryDirect makes a direct syscall to NtWriteVirtualMemory using Tartarus' Gate
func NtWriteVirtualMemoryDirect(processHandle windows.Handle, baseAddress uintptr, buffer unsafe.Pointer, bufferSize uintptr, bytesWritten *uintptr) error {
	return NtWriteVirtualMemory(processHandle, baseAddress, buffer, bufferSize, bytesWritten)
}

// NtProtectVirtualMemoryDirect makes a direct syscall to NtProtectVirtualMemory using Tartarus' Gate
func NtProtectVirtualMemoryDirect(processHandle windows.Handle, baseAddress *uintptr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) error {
	return NtProtectVirtualMemory(processHandle, baseAddress, regionSize, newProtect, oldProtect)
}

// NtCreateThreadExDirect makes a direct syscall to NtCreateThreadEx using Tartarus' Gate
func NtCreateThreadExDirect(threadHandle *windows.Handle, desiredAccess uint32, objectAttributes uintptr, processHandle windows.Handle, startAddress uintptr, parameter uintptr, createSuspended uint32, zeroBits uintptr, stackSize uintptr, maximumStackSize uintptr, attributeList uintptr) error {
	return NtCreateThreadEx(threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, zeroBits, stackSize, maximumStackSize, attributeList)
}