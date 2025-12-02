package common

import (
	"testing"
)

// TestHashString verifies the DJB2 hash implementation
func TestHashString(t *testing.T) {
	// Test known string with expected DJB2 hash
	testCases := []struct {
		input    string
		expected uint32
	}{
		{"kernel32.dll", uint32(1883303541)}, // Actual DJB2 hash for "kernel32.dll"
		{"NtAllocateVirtualMemory", uint32(1737737036)}, // Actual DJB2 hash for "NtAllocateVirtualMemory"
		{"", 5381}, // Empty string should return initial hash value
		{"a", 177670}, // Single character test
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := HashString(tc.input)
			if result != tc.expected {
				t.Errorf("HashString(%q) = %d, expected %d", tc.input, result, tc.expected)
			}
		})
	}
}

// TestHashStringConsistent verifies that the same string always produces the same hash
func TestHashStringConsistent(t *testing.T) {
	testString := "test_string_for_consistency"
	
	first := HashString(testString)
	second := HashString(testString)
	
	if first != second {
		t.Errorf("HashString is not consistent: %d != %d", first, second)
	}
}

// BenchmarkHashString provides performance metrics
func BenchmarkHashString(b *testing.B) {
	testString := "very_long_string_for_benchmarking_purposes"
	for i := 0; i < b.N; i++ {
		_ = HashString(testString)
	}
}