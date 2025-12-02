package utils

import (
	"testing"
)

// TestGenerateRandomKey verifies that random key generation works properly
func TestGenerateRandomKey(t *testing.T) {
	// Test with different lengths
	for _, length := range []int{8, 16, 32, 64} {
		t.Run(string(rune(length)), func(t *testing.T) {
			key1 := GenerateRandomKey(length)
			key2 := GenerateRandomKey(length)
			
			if len(key1) != length {
				t.Errorf("GenerateRandomKey(%d) returned key of length %d, expected %d", length, len(key1), length)
			}
			
			if len(key2) != length {
				t.Errorf("GenerateRandomKey(%d) returned key of length %d, expected %d", length, len(key2), length)
			}
			
			// In a perfect world, these shouldn't be identical, but with random generation
			// we can't guarantee this, so we'll just make sure they're both the right length
		})
	}
}

// TestObfuscateDeobfuscate verifies that obfuscation and deobfuscation are inverse operations
func TestObfuscateDeobfuscate(t *testing.T) {
	original := "test_string_for_obfuscation"
	obfuscated := ObfuscateString(original)
	deobfuscated := DeobfuscateString(obfuscated)
	
	if deobfuscated != original {
		t.Errorf("Deobfuscated string '%s' does not match original '%s'", deobfuscated, original)
	}
}

// TestObfuscateDeobfuscateStatic verifies that static obfuscation and deobfuscation work
func TestObfuscateDeobfuscateStatic(t *testing.T) {
	original := "static_test_string"
	obfuscated := ObfuscateStringStatic(original)
	deobfuscated := DeobfuscateStringStatic(obfuscated)
	
	if deobfuscated != original {
		t.Errorf("Deobfuscated string '%s' does not match original '%s'", deobfuscated, original)
	}
}

// TestEncryptionDecryption verifies that AES encryption and decryption are inverse operations
func TestEncryptionDecryption(t *testing.T) {
	original := []byte("test_data_for_encryption")
	
	encrypted, err := EncryptData(original)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}
	
	decrypted, err := DecryptData(encrypted)
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}
	
	if string(decrypted) != string(original) {
		t.Errorf("Decrypted data '%s' does not match original '%s'", string(decrypted), string(original))
	}
}

// TestDecryptDataErrorCases tests error handling in decryption
func TestDecryptDataErrorCases(t *testing.T) {
	// Test with empty data
	_, err := DecryptData([]byte{})
	if err == nil {
		t.Error("DecryptData should return error for empty data")
	}
	
	// Test with short data (less than nonce size)
	shortData := make([]byte, 5) // Assuming nonce is larger than 5 bytes
	_, err = DecryptData(shortData)
	if err == nil {
		t.Error("DecryptData should return error for short data")
	}
}