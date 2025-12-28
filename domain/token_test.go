package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestCreateAndDecryptPseudonym(t *testing.T) {
	// Create key-pair for receiving organization (Party B)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubKey := key.PublicKey

	// Party A:
	// --------

	// Prepare bsn
	blind, blindedElement, err := CreateBlindedIdentifier("bsn:1234567890")
	if err != nil {
		t.Fatalf("failed to create blinded token: %v", err)
	}

	// Send it to the pseudonym service

	// Service:
	// --------

	// create pseudonym for Party B
	token, err := CreateBlindedToken(blindedElement, "test-org", pubKey)
	if err != nil {
		t.Fatalf("failed to create blinded and encrypted pseudonym: %v", err)
	}

	// Send token and blind to Party B.

	// Party B:
	// --------

	// Decrypt and unblind the pseudonym
	pseudonym, err := DecryptAndUnblindToken(token, blind, *key)
	if err != nil {
		t.Fatalf("failed to decrypt and unblind token: %v", err)
	}

	// Recover BSN from pseudonym
	// first blind the pseudonym so the pseudonym service does not see the BSN
	blind2, blindedPseudonym, err := CreateBlindedPsuedonym(pseudonym)
	if err != nil {
		t.Fatalf("failed to create blinded token: %v", err)
	}

	blindedBSN, err := BlindedIdentifierFromBlindedPseudonym(blindedPseudonym, "test-org")
	if err != nil {
		t.Fatalf("failed to create blinded token from blinded pseudonym: %v", err)
	}

	unblindedBSN, err := Unblind(blind2, blindedBSN)
	if err != nil {
		t.Fatalf("failed to unblind BSN: %v", err)
	}

	// Trim null bytes from the recovered BSN (NewInput pads to 16 bytes)
	originalBSN := string(unblindedBSN)
	// Find first null byte and truncate
	for i, b := range unblindedBSN {
		if b == 0 {
			originalBSN = string(unblindedBSN[:i])
			break
		}
	}

	if originalBSN != "bsn:1234567890" {
		t.Fatalf("unblinded BSN does not match original: got %s, want %s", originalBSN, "bsn:1234567890")
	}
}
