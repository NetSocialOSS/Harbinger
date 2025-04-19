package middlewares

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"log"
	"strings"

	"netsocial/types"

	"github.com/goccy/go-yaml"
)

// Configuration struct for storing AES key
var configuration types.Config

func init() {
	configFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("[Harbinger] Failed to read config file: %v", err)
	}
	err = yaml.UnmarshalWithOptions(configFile, &configuration, yaml.DisallowUnknownField())
	if err != nil {
		log.Fatalf("[Harbinger] Failed to parse config file: %v", err)
	}
}

// EncryptAES encrypts a string using AES-GCM
func EncryptAES(plaintext string) (string, error) {
	aesKey := []byte(configuration.AESKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	// Generate a random nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Encode nonce and ciphertext in Base64
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Return combined nonce and encrypted text
	return nonceBase64 + ":" + ciphertextBase64, nil
}

// DecryptAES decrypts an AES-GCM encrypted string
func DecryptAES(encryptedText string) (string, error) {
	parts := strings.Split(encryptedText, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted text format")
	}

	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	aesKey := []byte(configuration.AESKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
