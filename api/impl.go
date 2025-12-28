package api

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/stevenvegt/pseudonyms/crypto"
	domain "github.com/stevenvegt/pseudonyms/domain"
	pb "github.com/stevenvegt/pseudonyms/proto"
)

// TODO: Should be passed in from main and not in the API section
// Example key (must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256)
var key = []byte("examplekey1234567890123456789012")

var _ StrictServerInterface = (*PseudonymService)(nil)

type PseudonymService struct {
	keysDir string
}

func NewPseudonymService(keysDir string) *PseudonymService {
	return &PseudonymService{keysDir: keysDir}
}

// getOrgPublicKey loads the public key for an organization from the filesystem
func (ps *PseudonymService) getOrgPublicKey(orgID string) (*rsa.PublicKey, error) {
	return crypto.LoadPublicKey(ps.keysDir, orgID)
}

// ExchangeIdentifier exchanges an identifier for a pseudonym or vice versa.
// Supports blinded operations for privacy-preserving exchanges.
func (ps *PseudonymService) ExchangeIdentifier(ctx context.Context, exchangeIdentifierRequest ExchangeIdentifierRequestObject) (ExchangeIdentifierResponseObject, error) {

	if exchangeIdentifierRequest.Body.Identifier == nil {
		return nil, fmt.Errorf("identifier is required")
	}

	if exchangeIdentifierRequest.Body.Identifier.Value == nil || exchangeIdentifierRequest.Body.Identifier.Type == nil {
		return nil, fmt.Errorf("identifier value and type are required")
	}

	if exchangeIdentifierRequest.Body.RecipientIdentifierType == nil {
		return nil, fmt.Errorf("recipient identifier type is required")
	}

	sourceIdentifierType := *exchangeIdentifierRequest.Body.Identifier.Type
	targetIdentifierType := *exchangeIdentifierRequest.Body.RecipientIdentifierType

	// For non-blinded types, source and target cannot be the same
	// (BLINDED_IDENTIFIER → BLINDED_IDENTIFIER is allowed: blinded pseudonym → blinded BSN)
	if sourceIdentifierType == targetIdentifierType && sourceIdentifierType != BLINDEDIDENTIFIER {
		return nil, fmt.Errorf("source and target identifier types cannot be the same")
	}

	// Handle blinded pseudonym unevaluation (blinded pseudonym → blinded BSN)
	if sourceIdentifierType == BLINDEDIDENTIFIER {
		blindedPseudonym := *exchangeIdentifierRequest.Body.Identifier.Value

		if exchangeIdentifierRequest.Body.Organisation == nil {
			return nil, fmt.Errorf("organisation is required for unevaluation")
		}

		// Unevaluate: remove org-specific key to get blinded BSN
		blindedBSN, err := domain.BlindedIdentifierFromBlindedPseudonym(blindedPseudonym, *exchangeIdentifierRequest.Body.Organisation)
		if err != nil {
			return nil, fmt.Errorf("failed to unevaluate blinded pseudonym: %v", err)
		}

		idType := BLINDEDIDENTIFIER
		return ExchangeIdentifier200JSONResponse{
			ExchangeIdentifierResponseJSONResponse{
				Identifier: &Identifier{Value: &blindedBSN, Type: &idType},
			},
		}, nil
	}

	// Legacy flow: non-blinded operations
	var (
		idValue  string
		idType   IdentifierTypes
		subject  string
		audience string
	)

	switch sourceIdentifierType {
	case BSN:
		if exchangeIdentifierRequest.Body.Organisation == nil {
			return nil, fmt.Errorf("organisation is required for BSN to pseudonym exchange")
		}
		audience = *exchangeIdentifierRequest.Body.Organisation
		subject = *exchangeIdentifierRequest.Body.Identifier.Value
	case ORGANISATIONPSEUDO:
		pseudonymString := *exchangeIdentifierRequest.Body.Identifier.Value
		pseudonym, err := domain.DecryptPseudonum(pseudonymString, key)
		if err != nil {
			return nil, err
		}
		subject = pseudonym.Subject
		audience = pseudonym.Audience
		if exchangeIdentifierRequest.Body.Organisation != nil && *exchangeIdentifierRequest.Body.Organisation != pseudonym.Audience {
			return nil, fmt.Errorf("organisation does not match pseudonym audience")
		}
		audience = pseudonym.Audience
	default:
		return nil, fmt.Errorf("unsupported identifier type: %s", *exchangeIdentifierRequest.Body.Identifier.Type)
	}

	switch targetIdentifierType {
	case BSN:
		idValue = subject
		idType = BSN
	case ORGANISATIONPSEUDO:
		pseudonym := &pb.Pseudonym{
			Subject:  subject,
			Audience: audience,
			Scope:    pb.Scope_TREATMENT,
			Version:  1,
		}

		pseudonymString, err := domain.CreatePseudonym(pseudonym, key)
		if err != nil {
			return nil, fmt.Errorf("failed to create pseudonym: %v", err)
		}
		idValue = pseudonymString
		idType = ORGANISATIONPSEUDO
	}

	return ExchangeIdentifier200JSONResponse{
		ExchangeIdentifierResponseJSONResponse{
			Identifier: &Identifier{Value: &idValue, Type: &idType},
		},
	}, nil
}

func (ps *PseudonymService) ExchangeToken(ctx context.Context, exchangeTokenRequest ExchangeTokenRequestObject) (ExchangeTokenResponseObject, error) {

	var (
		idValue string
		idType  IdentifierTypes
	)

	tokenString := *exchangeTokenRequest.Body.Token
	decryptedToken, err := domain.DecryptToken(tokenString, key)
	if err != nil {
		log.Fatal(err)
	}

	switch *exchangeTokenRequest.Body.IdentifierType {
	case BSN:
		idValue = decryptedToken.Subject
		idType = BSN
	case ORGANISATIONPSEUDO:
		pseudonym := &pb.Pseudonym{
			Subject:  decryptedToken.Subject,
			Audience: decryptedToken.Audience,
			Scope:    decryptedToken.Scopes[0],
			Version:  1,
		}

		pseudonymString, err := domain.CreatePseudonym(pseudonym, key)
		if err != nil {
			log.Fatal(err)
		}
		idValue = pseudonymString
		idType = ORGANISATIONPSEUDO
	}

	return ExchangeToken200JSONResponse{ExchangeTokenResponseJSONResponse{Identifier: &Identifier{
		Value: &idValue,
		Type:  &idType,
	}}}, nil
}

func (ps *PseudonymService) GetToken(ctx context.Context, getTokenRequest GetTokenRequestObject) (GetTokenResponseObject, error) {

	if getTokenRequest.Body.Receiver == nil {
		return nil, fmt.Errorf("receiver is required")
	}

	if getTokenRequest.Body.Identifier == nil || getTokenRequest.Body.Identifier.Type == nil {
		return nil, fmt.Errorf("identifier and type are required")
	}

	// Handle blinded identifiers differently - use blind evaluation
	if *getTokenRequest.Body.Identifier.Type == BLINDEDIDENTIFIER {
		blindedElement := *getTokenRequest.Body.Identifier.Value
		receiverOrg := *getTokenRequest.Body.Receiver

		// Get the receiver's public key
		pubKey, err := ps.getOrgPublicKey(receiverOrg)
		if err != nil {
			return nil, fmt.Errorf("failed to get receiver public key: %v", err)
		}

		// Evaluate the blinded element with org-specific key and encrypt for receiver
		encryptedToken, err := domain.CreateBlindedToken(blindedElement, receiverOrg, *pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create blinded token: %v", err)
		}

		return GetToken200JSONResponse{GetTokenResponseJSONResponse{Token: &encryptedToken}}, nil
	}

	// Handle non-blinded identifiers (legacy flow)
	var subject string

	switch *getTokenRequest.Body.Identifier.Type {
	case BSN:
		subject = *getTokenRequest.Body.Identifier.Value
	case ORGANISATIONPSEUDO:
		pseudonymString := *getTokenRequest.Body.Identifier.Value
		decryptedPseudonym, err := domain.DecryptPseudonum(pseudonymString, key)
		if err != nil {
			return nil, err
		}

		subject = decryptedPseudonym.Subject
	}

	now := time.Now()
	if getTokenRequest.Body.Sender == nil {
		return nil, fmt.Errorf("sender is required")
	}

	token := &pb.Token{
		Subject:    subject,
		Issuer:     *getTokenRequest.Body.Sender,
		Audience:   *getTokenRequest.Body.Receiver,
		Expiration: now.Add(time.Hour).Unix(),
		IssuedAt:   now.Unix(),
		Scopes:     []pb.Scope{pb.Scope_TREATMENT},
	}

	tokenString, err := domain.CreateToken(token, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	return GetToken200JSONResponse{GetTokenResponseJSONResponse{Token: &tokenString}}, nil
}
