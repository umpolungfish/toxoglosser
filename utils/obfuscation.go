package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"toxoglosser/common"
)

// XORKey is used to obfuscate strings - it's generated dynamically at runtime
var XORKey []byte

// init function to generate a random XOR key at runtime
func init() {
	// Generate a random key of 16 bytes (or any desired length)
	XORKey = GenerateRandomKey(16)
}

// GenerateRandomKey generates a random key of specified length
func GenerateRandomKey(length int) []byte {
	key := make([]byte, length)
	// Use cryptographic random number generator for proper key generation
	_, err := rand.Read(key)
	if err != nil {
		// If crypto random fails, use a fallback method
		// This is just a fallback and not cryptographically secure
		for i := 0; i < length; i++ {
			key[i] = byte((i * 17) % 256)
		}
	}
	return key
}

// ObfuscateString obfuscates a string using XOR with a key
func ObfuscateString(str string) []byte {
	data := []byte(str)
	result := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ XORKey[i%len(XORKey)]
	}

	return result
}

// DeobfuscateString deobfuscates a string using XOR with a key
func DeobfuscateString(data []byte) string {
	result := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ XORKey[i%len(XORKey)]
	}

	return string(result)
}

// EncryptData encrypts data using AES-GCM with a key derived from the XOR key
func EncryptData(plaintext []byte) ([]byte, error) {
	// Expand the XORKey to create a proper encryption key
	encryptionKey := expandKey(XORKey, 32) // 32 bytes for AES-256

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptData decrypts data using AES-GCM with a key derived from the XOR key
func DecryptData(ciphertext []byte) ([]byte, error) {
	// Expand the XORKey to create a proper encryption key
	encryptionKey := expandKey(XORKey, 32) // 32 bytes for AES-256

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// expandKey expands a short key to the desired length using a simple algorithm
func expandKey(key []byte, length int) []byte {
	if len(key) == 0 {
		// If key is empty, generate a random one
		return GenerateRandomKey(length)
	}

	expanded := make([]byte, length)
	for i := 0; i < length; i++ {
		expanded[i] = key[i%len(key)]
		// XOR with position to add variation
		expanded[i] ^= byte(i)
	}
	return expanded
}

// HashString is a wrapper around the common package HashString function
func HashString(s string) uint32 {
	return common.HashString(s)
}

// ObfuscateStringStatic obfuscates a string using compile-time obfuscation
// This version stores the obfuscated string which is then deobfuscated at runtime
func ObfuscateStringStatic(str string) []byte {
	// Use a fixed key for static obfuscation
	fixedKey := []byte("S13Sh3LL-0bfu5c4710n-K3y!")

	data := []byte(str)
	result := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ fixedKey[i%len(fixedKey)]
	}

	return result
}

// DeobfuscateStringStatic deobfuscates a string using the same key
func DeobfuscateStringStatic(obfuscated []byte) string {
	// Use the same fixed key for static deobfuscation
	fixedKey := []byte("S13Sh3LL-0bfu5c4710n-K3y!")

	result := make([]byte, len(obfuscated))

	for i := 0; i < len(obfuscated); i++ {
		result[i] = obfuscated[i] ^ fixedKey[i%len(fixedKey)]
	}

	return string(result)
}