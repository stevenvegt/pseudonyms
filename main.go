package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/agl/gcmsiv"
	pb "github.com/stevenvegt/pseudonyms/proto"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// Function to derive a deterministic nonce using SHA-256
func deriveNonce(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:12] // AES-GCM-SIV requires a 12-byte nonce
}

func encryptAESGCM_SIV(key []byte, plaintext []byte, additionalData []byte) ([]byte, []byte, error) {

	aesGCNSIV, err := gcmsiv.NewGCMSIV(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES-GCM-SIV block cipher: %v", err)
	}

	nonce := deriveNonce(append(plaintext, additionalData...))

	ciphertext := aesGCNSIV.Seal(nil, nonce, plaintext, additionalData)

	return nonce, ciphertext, nil
}

func decryptAESGCM_SIV(key []byte, nonce, ciphertext []byte, additionalData []byte) (string, error) {
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
func encryptAESGCM(key []byte, plaintext []byte, additionalData []byte) ([]byte, []byte, error) {
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
func decryptAESGCM(key []byte, nonce, ciphertext, additionalData []byte) ([]byte, error) {
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

func createToken(token *pb.Token, key []byte) (string, error) {
	header := pb.Header{
		Version:     pb.Version_V1,
		ContentType: pb.ContentType_TOKEN,
	}

	tokenData, err := proto.Marshal(token)
	if err != nil {
		return "", err
	}

	aadData, err := proto.Marshal(&header)
	if err != nil {
		return "", err
	}

	// Encrypt the data using AES-GCM
	nonce, ciphertext, err := encryptAESGCM(key, tokenData, aadData)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %v", err)
	}

	container := pb.Container{
		Nonce:      nonce,
		Header:     &header,
		Ciphertext: ciphertext,
	}

	tokenContainer, err := prototext.Marshal(&container)
	if err != nil {
		log.Fatal(err)
	}

	// jsonTokenContainer, err := json.Marshal(&container)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	b64TokenContainer := base64.StdEncoding.EncodeToString(tokenContainer)

	// fmt.Printf("Token Container: %s\n", tokenContainer)
	// fmt.Printf("Token Container (JSON): %s\n", jsonTokenContainer)
	// fmt.Printf("Token Container (Base64): %s\n", b64TokenContainer)

	return b64TokenContainer, nil
}

func decryptToken(tokenString string, key []byte) (*pb.Token, error) {
	tokenContainer, err := base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		return nil, err
	}

	container := pb.Container{}
	err = prototext.Unmarshal(tokenContainer, &container)
	if err != nil {
		return nil, err
	}

	aad := []byte{}
	if container.Header != nil {
		aad, err = proto.Marshal(container.Header)
		if err != nil {
			return nil, err
		}
	}

	// Decrypt the data using AES-GCM
	plaintext, err := decryptAESGCM(key, container.Nonce, container.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	token := pb.Token{}
	err = proto.Unmarshal(plaintext, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func createPseudonym(ps *pb.Pseudonym, key []byte) (string, error) {
	header := pb.Header{
		Version:     pb.Version_V1,
		ContentType: pb.ContentType_PSEUDONYM,
	}

	pseudonymData, err := proto.Marshal(ps)
	if err != nil {
		return "", err
	}

	aadData, err := proto.Marshal(&header)
	if err != nil {
		return "", err
	}

	// Encrypt the data using AES-GCM-SIV
	nonce, ciphertext, err := encryptAESGCM_SIV(key, pseudonymData, aadData)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %v", err)
	}

	container := pb.Container{
		Nonce:      nonce,
		Header:     &header,
		Ciphertext: ciphertext,
	}

	tokenContainer, err := prototext.Marshal(&container)
	if err != nil {
		log.Fatal(err)
	}

	b64TokenContainer := base64.StdEncoding.EncodeToString(tokenContainer)

	return b64TokenContainer, nil
}

func decryptPseudonum(pseudonymString string, key []byte) (*pb.Pseudonym, error) {
	tokenContainer, err := base64.StdEncoding.DecodeString(pseudonymString)
	if err != nil {
		return nil, err
	}

	container := pb.Container{}
	err = prototext.Unmarshal(tokenContainer, &container)
	if err != nil {
		return nil, err
	}

	aad := []byte{}
	if container.Header != nil {
		aad, err = proto.Marshal(container.Header)
		if err != nil {
			return nil, err
		}
	}

	// Decrypt the data using AES-GCM-SIV
	plaintext, err := decryptAESGCM_SIV(key, container.Nonce, container.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	pseudonym := pb.Pseudonym{}
	err = proto.Unmarshal([]byte(plaintext), &pseudonym)
	if err != nil {
		return nil, err
	}

	return &pseudonym, nil
}

// Main function
func main() {
	// Example key (must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256)
	key := []byte("examplekey1234567890123456789012")

	now := time.Now()

	token := &pb.Token{
		Subject:    "123456789",
		Issuer:     "222123456",
		Audience:   "444123456",
		Expiration: now.Add(time.Hour).Unix(),
		IssuedAt:   now.Unix(),
		Scopes:     []pb.Scope{pb.Scope_TREATMENT},
	}

	tokenString, err := createToken(token, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token: %s\n", tokenString)

	decryptedToken, err := decryptToken(tokenString, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted Token: %v\n", decryptedToken)

	pseudonym := &pb.Pseudonym{
		Subject:  decryptedToken.Subject,
		Audience: decryptedToken.Audience,
		Scopes:   decryptedToken.Scopes,
		Version:  1,
	}

	pseudonymString, err := createPseudonym(pseudonym, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Pseudonym: %s\n", pseudonymString)

	decryptedPseudonym, err := decryptPseudonum(pseudonymString, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted Pseudonym: %v\n", decryptedPseudonym)

}
