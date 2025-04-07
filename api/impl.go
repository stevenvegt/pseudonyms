package api

import (
	"context"
	"fmt"
	"log"
	"time"

	domain "github.com/stevenvegt/pseudonyms/domain"
	pb "github.com/stevenvegt/pseudonyms/proto"
)

// TODO: Should be passed in from main and not in the API section
// Example key (must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256)
var key = []byte("examplekey1234567890123456789012")

var _ StrictServerInterface = (*PseudonymService)(nil)

type PseudonymService struct {
}

func NewPseudonymService() *PseudonymService {
	return &PseudonymService{}
}

// ExchangeIdentifier exchanges an identifier for a pseudonym or vice versa.
// So, As an organisation, if you have a BSN, you can get your own pseudonym. Or, if you have a pseudonym, you can get the BSN of the subject.
func (ps *PseudonymService) ExchangeIdentifier(ctx context.Context, exchangeIdentifierRequest ExchangeIdentifierRequestObject) (ExchangeIdentifierResponseObject, error) {

	var (
		idValue  string
		idType   IdentifierTypes
		subject  string
		audience string
	)

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

	if sourceIdentifierType == targetIdentifierType {
		return nil, fmt.Errorf("source and target identifier types cannot be the same")
	}

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
			log.Fatal(err)
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

	var (
		subject string
	)

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
		log.Fatal(err)
	}

	return GetToken200JSONResponse{GetTokenResponseJSONResponse{Token: &tokenString}}, nil
}
