package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/stevenvegt/pseudonyms/api"
)

func main() {
	keysDir := flag.String("keys-dir", "./keys", "Directory containing organization key files")
	flag.Parse()

	// Validate keys directory exists
	if info, err := os.Stat(*keysDir); err != nil || !info.IsDir() {
		log.Fatalf("Keys directory does not exist or is not a directory: %s", *keysDir)
	}

	server := api.NewPseudonymService(*keysDir)
	strictHandler := api.NewStrictHandler(server, nil)

	mux := http.NewServeMux()
	handler := api.HandlerFromMux(strictHandler, mux)

	s := &http.Server{
		Handler: handler,
		Addr:    "0.0.0.0:8082",
	}

	// And we serve HTTP until the world ends.
	log.Fatal(s.ListenAndServe())
}

// Example usage function
// func example() {
// 	// Example key (must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256)
// 	key := []byte("examplekey1234567890123456789012")
//
// 	now := time.Now()
//
// 	token := &pb.Token{
// 		Subject:    "123456789",
// 		Issuer:     "222123456",
// 		Audience:   "444123456",
// 		Expiration: now.Add(time.Hour).Unix(),
// 		IssuedAt:   now.Unix(),
// 		Scopes:     []pb.Scope{pb.Scope_TREATMENT},
// 	}
//
// 	tokenString, err := createToken(token, key)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	fmt.Printf("Token: %s\n", tokenString)
//
// 	decryptedToken, err := decryptToken(tokenString, key)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	fmt.Printf("Decrypted Token: %v\n", decryptedToken)
//
// 	pseudonym := &pb.Pseudonym{
// 		Subject:  decryptedToken.Subject,
// 		Audience: decryptedToken.Audience,
// 		Scope:    decryptedToken.Scopes[0],
// 		Version:  1,
// 	}
//
// 	pseudonymString, err := createPseudonym(pseudonym, key)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	fmt.Printf("Pseudonym: %s\n", pseudonymString)
//
// 	decryptedPseudonym, err := decryptPseudonum(pseudonymString, key)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	fmt.Printf("Decrypted Pseudonym: %v\n", decryptedPseudonym)
//
// }
