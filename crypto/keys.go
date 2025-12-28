package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// LoadPublicKey loads an RSA public key from a PEM file.
// The file is expected at {keysDir}/{orgID}.pub
func LoadPublicKey(keysDir, orgID string) (*rsa.PublicKey, error) {
	path := filepath.Join(keysDir, orgID+".pub")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key from %s: %w", path, err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key in %s is not an RSA key", path)
	}

	return rsaPub, nil
}

// LoadPrivateKey loads an RSA private key from a PEM file.
// The file is expected at {keysDir}/{orgID}.key
func LoadPrivateKey(keysDir, orgID string) (*rsa.PrivateKey, error) {
	path := filepath.Join(keysDir, orgID+".key")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}

	// Try PKCS#1 format first (RSA PRIVATE KEY)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privKey, nil
	}

	// Try PKCS#8 format (PRIVATE KEY)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from %s: %w", path, err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key in %s is not an RSA key", path)
	}

	return rsaKey, nil
}
