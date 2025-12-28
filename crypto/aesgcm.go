package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/agl/gcmsiv"
)

// Function to derive a deterministic nonce using SHA-256
func deriveNonce(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:12] // AES-GCM-SIV requires a 12-byte nonce
}

func EncryptAESGCM_SIV(key []byte, plaintext []byte, additionalData []byte) ([]byte, []byte, error) {

	aesGCNSIV, err := gcmsiv.NewGCMSIV(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES-GCM-SIV block cipher: %v", err)
	}

	nonce := deriveNonce(append(plaintext, additionalData...))

	ciphertext := aesGCNSIV.Seal(nil, nonce, plaintext, additionalData)

	return nonce, ciphertext, nil
}

func DecryptAESGCM_SIV(key []byte, nonce, ciphertext []byte, additionalData []byte) (string, error) {
	aesGCNSIV, err := gcmsiv.NewGCMSIV(key)
	if err != nil {
		return "", err
	}

	plaintext, err := aesGCNSIV.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Encrypt function using AES-GCM-SIV
func EncryptAESGCM(key []byte, plaintext []byte, additionalData []byte) ([]byte, []byte, error) {
	// Create AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES block cipher: %v", err)
	}

	// Create AES-GCM-SIV cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES-GCM-SIV cipher: %v", err)
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// Encrypt the plaintext
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, additionalData)

	return nonce, ciphertext, nil
}

// Decrypt function
func DecryptAESGCM(key []byte, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	// Create AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create AES-GCM-SIV cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
