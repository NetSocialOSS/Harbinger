package middlewares

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

// Function to retrieve the AES key from environment variables
func getAESKey() ([]byte, error) {
	key := os.Getenv("aeskey")
	if len(key) != 32 { // AES-256 requires a 32-byte key
		return nil, errors.New("AES key must be exactly 32 bytes")
	}
	return []byte(key), nil
}

// EncryptAES function to encrypt a string using AES GCM encryption
func EncryptAES(plaintext string) (string, error) {
	aesKey, err := getAESKey() // Retrieve the AES key
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	// Generate a random nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12) // AES-GCM recommends 12-byte nonce
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	// Create a GCM cipher mode with the AES key and nonce
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the data using AES-GCM
	plaintextBytes := []byte(plaintext)
	ciphertext := gcm.Seal(nil, nonce, plaintextBytes, nil)

	// Encode the nonce and ciphertext in base64 and return
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

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
	nonce, err := base64.StdEncoding.DecodeString(nonceBase64)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}

	aesKey, err := getAESKey() // Retrieve the AES key
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	// Create a GCM cipher mode with the AES key
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt the data using AES-GCM
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	// Return the decrypted plaintext as a string
	return string(plaintext), nil
}
