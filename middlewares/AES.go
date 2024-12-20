package middlewares

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const nonceSize = 12 // AES-GCM recommends 12-byte nonce

// Function to retrieve the AES key from environment variables
func getAESKey() ([]byte, error) {
	key := os.Getenv("aeskey")
	if len(key) != 32 { // AES-256 requires a 32-byte key
		return nil, fmt.Errorf("AES key must be exactly 32 bytes, got %d bytes", len(key))
	}
	return []byte(key), nil
}

// EncryptAES function to encrypt a string using AES GCM encryption
func EncryptAES(plaintext string) (string, error) {
	aesKey, err := getAESKey() // Retrieve the AES key
	if err != nil {
		return "", fmt.Errorf("failed to get AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create new cipher: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create a GCM cipher mode with the AES key and nonce
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt the data using AES-GCM
	plaintextBytes := []byte(plaintext)
	ciphertext := gcm.Seal(nil, nonce, plaintextBytes, nil)

	// Encode the nonce and ciphertext in base64 and return
	nonceBase64 := base64.URLEncoding.EncodeToString(nonce)
	ciphertextBase64 := base64.URLEncoding.EncodeToString(ciphertext)

	// Return the nonce and encrypted text in the format: nonce:ciphertext
	return nonceBase64 + ":" + ciphertextBase64, nil
}

// DecryptAES function to decrypt a string using AES GCM encryption
func DecryptAES(encryptedText string) (string, error) {
	// Split the encrypted text to get the nonce and ciphertext
	parts := strings.Split(encryptedText, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted text format")
	}

	nonceBase64 := parts[0]
	ciphertextBase64 := parts[1]

	// Decode the base64 strings
	nonce, err := base64.URLEncoding.DecodeString(nonceBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := base64.URLEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	aesKey, err := getAESKey() // Retrieve the AES key
	if err != nil {
		return "", fmt.Errorf("failed to get AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create new cipher: %w", err)
	}

	// Create a GCM cipher mode with the AES key
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data using AES-GCM
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Return the decrypted plaintext as a string
	return string(plaintext), nil
}
