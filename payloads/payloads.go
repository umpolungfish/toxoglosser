package payloads

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// DecryptPayload decrypts an encrypted payload using AES
func DecryptPayload(data, key []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("payload too small to be encrypted")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The first 16 bytes are the IV
	iv := data[:16]
	ciphertext := data[16:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// EncryptPayload encrypts a payload using AES
func EncryptPayload(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// ValidatePayload checks if the payload is valid
func ValidatePayload(data []byte) bool {
	// Basic validation - check for common shellcode patterns
	// This is a simplified check
	if len(data) == 0 {
		return false
	}
	
	// Check for common x64 shellcode prefixes
	if len(data) >= 2 {
		// Common x64 shellcode prefixes
		if data[0] == 0x48 && data[1] == 0x31 { // xor rax, rax
			return true
		}
	}
	
	// Additional validation checks would go here
	return true
}