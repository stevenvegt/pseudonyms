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
		log.Fatal(err)
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
