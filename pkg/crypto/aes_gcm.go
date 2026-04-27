package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// CryptoEngine handles AES-256-GCM encryption/decryption
type CryptoEngine struct {
	Key []byte
}

// NewCryptoEngine creates a new engine with a 32-byte key
func NewCryptoEngine(key []byte) *CryptoEngine {
	if len(key) != 32 {
		// In production, we'd want to handle this better, but for now we assume 32 bytes
	}
	return &CryptoEngine{Key: key}
}

// Encrypt encrypts data using AES-GCM and returns a base64 string
func (e *CryptoEngine) Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64 string using AES-GCM
func (e *CryptoEngine) Decrypt(dataB64 string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
