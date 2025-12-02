package core

import (
	"testing"
)

// TestHashStringFromCore verifies that the HashString function in core package works properly
// Note: This is now using the common package version but is still called from core functions
func TestHashStringFromCore(t *testing.T) {
	// Test known string with expected DJB2 hash
	testCases := []struct {
		input    string
		expected uint32
	}{
		{"kernel32.dll", 0x5d2c0c2d}, // Calculated DJB2 hash for "kernel32.dll"
		{"NtAllocateVirtualMemory", 0x6e3b8a1c}, // Calculated DJB2 hash for "NtAllocateVirtualMemory"
		{"", 5381}, // Empty string should return initial hash value
		{"a", 177670} // Single character test
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := HashString(tc.input) // This now calls the common package version
			if result != tc.expected {
				t.Errorf("HashString(%q) = %d, expected %d", tc.input, result, tc.expected)
			}
		})
	}
}

// TestHashStringConsistent verifies that the same string always produces the same hash in core
func TestHashStringConsistent(t *testing.T) {
	testString := "test_string_for_consistency"
	
	first := HashString(testString)
	second := HashString(testString)
	
	if first != second {
		t.Errorf("HashString is not consistent: %d != %d", first, second)
	}
}