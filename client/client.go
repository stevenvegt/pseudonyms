package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	api "github.com/stevenvegt/pseudonyms/client/api"
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
		runReceiver(ctx, client, *token, *blind, *privKeyOrg, *receiverOrg)
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

func runReceiver(ctx context.Context, client *api.ClientWithResponses, encryptedToken string, blindInitiator string, orgID string, receiverOrg string) {
	if encryptedToken == "" || blindInitiator == "" {
		fmt.Fprintf(os.Stderr, "Receiver mode requires -token and -blind parameters\n")
		os.Exit(1)
	}

	if orgID == "" {
		fmt.Fprintf(os.Stderr, "Receiver mode requires -org parameter for private key lookup\n")
		os.Exit(1)
	}

	fmt.Println("=== Receiver: Recovering BSN from pseudonym ===")
	fmt.Println()

	// Step 1: Decrypt and unblind the token to get pseudonym
	// NOTE: This requires Receiver's private key which is stored on the server
	// In production, this would be an API call that does decryption server-side
	fmt.Println("1. Decrypting and unblinding token")
	fmt.Println("   [NOTE: Requires Receiver's private key - would be done server-side]")
	fmt.Println("   [For this demo, we cannot complete this step without the private key]")
	fmt.Println()

	// In a real implementation, Receiver would have their private key or call an API
	// that uses it. For now, we'll demonstrate the second part of the flow:
	// converting a pseudonym back to BSN

	fmt.Println("2. Assuming Receiver has the pseudonym, they can recover the BSN:")
	fmt.Println("   a. Blind the pseudonym")
	fmt.Println("   b. Send to service for unevaluation")
	fmt.Println("   c. Unblind the result to get original BSN")
	fmt.Println()

	// Example: if Receiver had a pseudonym
	fmt.Println("Example flow (if pseudonym was available):")
	fmt.Println("  pseudonymBase64 := \"<received from Initiator>\"")
	fmt.Println("  blind2, blindedPseudonym := domain.CreateBlindedPsuedonym(pseudonymBase64)")
	fmt.Println()
	fmt.Println("  // Send to service")
	fmt.Println("  blindedIdType := api.BLINDEDIDENTIFIER")
	fmt.Println("  exchangeReq := api.ExchangeIdentifierJSONRequestBody{")
	fmt.Println("    Identifier: &api.Identifier{Type: &blindedIdType, Value: &blindedPseudonym},")
	fmt.Println("    RecipientIdentifierType: &blindedIdType,")
	fmt.Printf("    Organisation: \"%s\",\n", receiverOrg)
	fmt.Println("  }")
	fmt.Println("  resp := client.ExchangeIdentifierWithResponse(ctx, exchangeReq)")
	fmt.Println()
	fmt.Println("  // Unblind to get BSN")
	fmt.Println("  blindedBSN := resp.JSON200.Identifier.Value")
	fmt.Println("  recoveredBSN := domain.Unblind(blind2, blindedBSN)")
	fmt.Println()
	fmt.Println("=== Receiver Flow Complete ===")
	fmt.Println("Note: Full implementation requires private key management on client or server-side API.")
}
