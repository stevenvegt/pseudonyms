package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	api "github.com/stevenvegt/pseudonyms/client/api"
	"github.com/stevenvegt/pseudonyms/crypto"
	"github.com/stevenvegt/pseudonyms/domain"
)

func main() {
	// Command-line flags
	mode := flag.String("mode", "initiator", "Mode: 'initiator' or 'receiver'")
	bsn := flag.String("bsn", "bsn:1234567890", "BSN identifier (initiator mode)")
	receiverOrg := flag.String("receiver-org", "hospital-b", "Receiver organization")
	token := flag.String("token", "", "Encrypted token (receiver mode)")
	blind := flag.String("blind", "", "Blind value (receiver mode)")
	privKeyOrg := flag.String("org", "", "Organization ID for private key lookup (receiver mode)")
	keysDir := flag.String("keys-dir", "./keys", "Directory containing organization key files")
	serverURL := flag.String("server", "http://localhost:8082", "Server URL")

	flag.Parse()

	client, err := api.NewClientWithResponses(*serverURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	switch *mode {
	case "initiator":
		runInitiator(ctx, client, *bsn, *receiverOrg)
	case "receiver":
		runReceiver(ctx, client, *token, *blind, *privKeyOrg, *keysDir, *receiverOrg)
	default:
		fmt.Fprintf(os.Stderr, "Invalid mode: %s. Use 'initiator' or 'receiver'\n", *mode)
		os.Exit(1)
	}
}

func runInitiator(ctx context.Context, client *api.ClientWithResponses, bsn string, receiverOrg string) {
	fmt.Println("=== Initiator: Creating pseudonym for Receiver ===")
	fmt.Println()

	// Step 1: Blind the BSN
	blind, blindedElement, err := domain.CreateBlindedIdentifier(bsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to blind BSN: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("1. Blinded BSN identifier")
	fmt.Printf("   Blind (keep secret): %s\n", blind)
	fmt.Printf("   Blinded element: %s\n", blindedElement)
	fmt.Println()

	// Step 2: Send blinded element to service
	blindedIdType := api.BLINDEDIDENTIFIER
	getTokenReq := api.GetTokenJSONRequestBody{
		Identifier: &api.Identifier{
			Type:  &blindedIdType,
			Value: &blindedElement,
		},
		Receiver: &receiverOrg,
	}

	fmt.Printf("2. Requesting token from service for receiver: %s\n", receiverOrg)
	tokenResp, err := client.GetTokenWithResponse(ctx, getTokenReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get token: %v\n", err)
		os.Exit(1)
	}

	if tokenResp.JSON200 == nil {
		fmt.Fprintf(os.Stderr, "Unexpected response: %s\n", tokenResp.Status())
		os.Exit(1)
	}

	encryptedToken := *tokenResp.JSON200.Token
	fmt.Printf("   Encrypted token received: %s\n", encryptedToken)
	fmt.Println()

	// Step 3: Output for Receiver
	fmt.Println("=== Output for Receiver ===")
	fmt.Printf("Token: %s\n", encryptedToken)
	fmt.Printf("Blind: %s\n", blind)
	fmt.Println()
	fmt.Println("Initiator should send both token and blind to Receiver via secure channel.")
}

func runReceiver(ctx context.Context, client *api.ClientWithResponses, encryptedToken string, blindInitiator string, orgID string, keysDir string, receiverOrg string) {
	if encryptedToken == "" || blindInitiator == "" {
		fmt.Fprintf(os.Stderr, "Receiver mode requires -token and -blind parameters\n")
		os.Exit(1)
	}

	if orgID == "" {
		fmt.Fprintf(os.Stderr, "Receiver mode requires -org parameter for private key lookup\n")
		os.Exit(1)
	}

	fmt.Println("=== Receiver: Recovering Pseudonym ===")
	fmt.Println()

	// Step 1: Load private key from filesystem
	fmt.Printf("1. Loading private key for organization: %s\n", orgID)
	privKey, err := crypto.LoadPrivateKey(keysDir, orgID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("   Private key loaded successfully")
	fmt.Println()

	// Step 2: Decrypt and unblind the token to get pseudonym
	fmt.Println("2. Decrypting and unblinding token")
	pseudonym, err := domain.DecryptAndUnblindToken(encryptedToken, blindInitiator, *privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt and unblind token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Pseudonym recovered: %s\n", pseudonym)
	fmt.Println()

	// Step 3: Optionally recover BSN by blinding pseudonym and calling ExchangeIdentifier
	fmt.Println("3. Recovering original BSN from pseudonym")

	// Blind the pseudonym
	blind2, blindedPseudonym, err := domain.CreateBlindedPsuedonym(pseudonym)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to blind pseudonym: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Blinded pseudonym: %s\n", blindedPseudonym)
	fmt.Println()

	// Send to service for unevaluation
	blindedIdType := api.BLINDEDIDENTIFIER
	exchangeReq := api.ExchangeIdentifierJSONRequestBody{
		Identifier: &api.Identifier{
			Type:  &blindedIdType,
			Value: &blindedPseudonym,
		},
		RecipientIdentifierType: &blindedIdType,
		Organisation:            &receiverOrg,
	}

	fmt.Println("4. Calling ExchangeIdentifier to unevaluate blinded pseudonym")
	resp, err := client.ExchangeIdentifierWithResponse(ctx, exchangeReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to exchange identifier: %v\n", err)
		os.Exit(1)
	}

	if resp.JSON200 == nil {
		fmt.Fprintf(os.Stderr, "Unexpected response: %s\n", resp.Status())
		os.Exit(1)
	}

	blindedBSN := *resp.JSON200.Identifier.Value
	fmt.Printf("   Blinded BSN received: %s\n", blindedBSN)
	fmt.Println()

	// Unblind to get original BSN
	fmt.Println("5. Unblinding to recover original BSN")
	recoveredBSN, err := domain.Unblind(blind2, blindedBSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to unblind BSN: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Recovered BSN: %s\n", string(recoveredBSN))
	fmt.Println()

	fmt.Println("=== Receiver Flow Complete ===")
}
