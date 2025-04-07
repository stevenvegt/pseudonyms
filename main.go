package main

import (
	"log"
	"net/http"

	"github.com/stevenvegt/pseudonyms/api"
)

func main() {
	server := api.NewPseudonymService()
	strictHandler := api.NewStrictHandler(server, nil)

	mux := http.NewServeMux()
	handler := api.HandlerFromMux(strictHandler, mux)

	s := &http.Server{
		Handler: handler,
		Addr:    "0.0.0.0:8080",
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
