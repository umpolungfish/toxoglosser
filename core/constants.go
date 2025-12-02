package core

import "golang.org/x/sys/windows"

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	MEM_COMMIT_RESERVE     = MEM_COMMIT | MEM_RESERVE
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PROCESS_ALL_ACCESS     = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFF
)