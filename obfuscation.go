// Package utils provides utility functions for Toxoglosser toolkit
// including string obfuscation, encryption, and other helper functions.
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// XORKey is used to obfuscate strings - it's generated dynamically at runtime
var XORKey []byte

// init function to generate a random XOR key at runtime
func init() {
	// Generate a random key of 16 bytes (or any desired length)
	XORKey = GenerateRandomKey(16)
}

// GenerateRandomKey generates a random key of specified length using a cryptographically secure method.
// If crypto random generation fails, it falls back to a deterministic method (not cryptographically secure).
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

// ObfuscateString obfuscates a string using XOR with a dynamically generated key.
// The key is generated at runtime and stored in the global XORKey variable.
func ObfuscateString(str string) []byte {
	data := []byte(str)
	result := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ XORKey[i%len(XORKey)]
	}

	return result
}

// DeobfuscateString deobfuscates data using XOR with the same key used for obfuscation.
// The key is the global XORKey variable that was generated at runtime.
func DeobfuscateString(data []byte) string {
	result := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ XORKey[i%len(XORKey)]
	}

	return string(result)
}

// EncryptData encrypts plaintext using AES-GCM with a key derived from the runtime XOR key.
// Returns the encrypted data or an error if encryption fails.
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

// DecryptData decrypts ciphertext using AES-GCM with a key derived from the runtime XOR key.
// Returns the decrypted data or an error if decryption fails.
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
// that XORs with position to add variation.
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

// ObfuscateStringStatic obfuscates a string using compile-time obfuscation.
// This version stores the obfuscated string which is then deobfuscated at runtime.
// Uses a fixed key for obfuscation.
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

// DeobfuscateStringStatic deobfuscates a string using the same fixed key.
// This is the reverse operation of ObfuscateStringStatic.
func DeobfuscateStringStatic(obfuscated []byte) string {
	// Use the same fixed key for static deobfuscation
	fixedKey := []byte("S13Sh3LL-0bfu5c4710n-K3y!")

	result := make([]byte, len(obfuscated))

	for i := 0; i < len(obfuscated); i++ {
		result[i] = obfuscated[i] ^ fixedKey[i%len(fixedKey)]
	}

	return string(result)
}