package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/stevenvegt/pseudonyms/crypto"
	blinding "github.com/stevenvegt/pseudonyms/crypto"
	pb "github.com/stevenvegt/pseudonyms/proto"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func CreateBlindedIdentifier(identifier string) (string, string, error) {
	inputBytes := blinding.NewInput(identifier)
	blind, blindedElement, err := blinding.Blind(inputBytes)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(blind), base64.StdEncoding.EncodeToString(blindedElement), nil
}

func CreateBlindedPsuedonym(pseudonym string) (string, string, error) {
	// Decode the base64-encoded pseudonym (marshaled Ristretto point)
	decoded, err := base64.StdEncoding.DecodeString(pseudonym)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode pseudonym: %v", err)
	}
	if len(decoded) != 32 {
		return "", "", fmt.Errorf("invalid pseudonym length: expected 32 bytes, got %d", len(decoded))
	}

	// Blind the marshaled point using the crypto module
	blindBytes, blindedPointBytes, err := blinding.BlindMarshaledPoint(decoded)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(blindBytes), base64.StdEncoding.EncodeToString(blindedPointBytes), nil
}

func CreateBlindedToken(blindedElementStr string, audience string, pubKey rsa.PublicKey) (string, error) {
	blindedElement, err := base64.StdEncoding.DecodeString(blindedElementStr)
	if err != nil {
		return "", err
	}
	key := blinding.KeyForOrgID(audience)
	evaluatedElement, err := blinding.BlindEvaluate(key, blindedElement)
	if err != nil {
		return "", err
	}

	encryptedBlindedElement, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, evaluatedElement)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBlindedElement), nil
}

func DecryptAndUnblindToken(encryptedBlindedElementB64 string, blindB64 string, privKey rsa.PrivateKey) (string, error) {
	encryptedBlindedElement, err := base64.StdEncoding.DecodeString(encryptedBlindedElementB64)
	if err != nil {
		return "", err
	}
	blindedElementBytes, err := rsa.DecryptPKCS1v15(nil, &privKey, encryptedBlindedElement)
	if err != nil {
		return "", err
	}
	blind, err := base64.StdEncoding.DecodeString(blindB64)
	p, err := blinding.Unblind(blind, blindedElementBytes)
	if err != nil {
		return "", fmt.Errorf("unblinding failed: %v", err)
	}
	// Return the marshaled point as the pseudonym, not the unembedded bytes
	pseudonymBytes, err := p.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal pseudonym: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pseudonymBytes), nil
}

func BlindedIdentifierFromBlindedPseudonym(blindedPseudonym string) (string, error) {
	blindedElement, err := base64.StdEncoding.DecodeString(blindedPseudonym)
	if err != nil {
		return "", err
	}
	key := blinding.KeyForOrgID("test-org")
	unevaluatedElement, err := blinding.Unevaluate(key, blindedElement)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(unevaluatedElement), nil
}

func Unblind(blindB64 string, blindedElementB64 string) ([]byte, error) {
	blind, err := base64.StdEncoding.DecodeString(blindB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blind")
	}
	blindedElement, err := base64.StdEncoding.DecodeString(blindedElementB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blinded element")
	}
	unblinded, err := blinding.Unblind(blind, blindedElement)
	if err != nil {
		return nil, fmt.Errorf("unblinding failed: %v", err)
	}
	rawUnblindedValue, err := blinding.Unembed(unblinded), nil
	if err != nil {
		return nil, err
	}

	// Trim null bytes from the recovered value (NewInput pads to 16 bytes)
	originalValue := rawUnblindedValue
	// Find first null byte and truncate
	for i, b := range rawUnblindedValue {
		if b == 0 {
			originalValue = rawUnblindedValue[:i]
			break
		}
	}
	return originalValue, nil
}

func CreateToken(token *pb.Token, key []byte) (string, error) {
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
	nonce, ciphertext, err := crypto.EncryptAESGCM(key, tokenData, aadData)
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
		return "", fmt.Errorf("failed to marshal token container: %v", err)
	}

	b64TokenContainer := base64.StdEncoding.EncodeToString(tokenContainer)

	return b64TokenContainer, nil
}

func DecryptToken(tokenString string, key []byte) (*pb.Token, error) {
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
	plaintext, err := crypto.DecryptAESGCM(key, container.Nonce, container.Ciphertext, aad)
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
