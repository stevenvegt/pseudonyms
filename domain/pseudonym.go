package domain

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/stevenvegt/pseudonyms/crypto"
	pb "github.com/stevenvegt/pseudonyms/proto"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func CreatePseudonym(ps *pb.Pseudonym, key []byte) (string, error) {
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
	nonce, ciphertext, err := crypto.EncryptAESGCM_SIV(key, pseudonymData, aadData)
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

func DecryptPseudonum(pseudonymString string, key []byte) (*pb.Pseudonym, error) {
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
	plaintext, err := crypto.DecryptAESGCM_SIV(key, container.Nonce, container.Ciphertext, aad)
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
