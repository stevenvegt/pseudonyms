package crypto

import (
	"errors"
	"fmt"

	"github.com/bwesterb/go-ristretto"
)

// Blind:
//
// Input:
//
//   PrivateInput input
//
// Output:
//
//   Scalar blind
//   Element blindedElement
//
// Parameters:
//
//   Group G
//
// Errors: InvalidInputError
//
// def Blind(input):
//   blind = G.RandomScalar()
//   inputElement = G.HashToGroup(input)
//   if inputElement == G.Identity():
//     raise InvalidInputError
//   blindedElement = blind * inputElement
//
//   return blind, blindedElement

var InvalidInputError = errors.New("invalid input: maps to identity element")

func Blind(input []byte) ([]byte, []byte, error) {
	var blind ristretto.Scalar
	blind.Rand()

	var identity ristretto.Point
	identity.SetZero()

	inputElement := Embed(input)
	if inputElement.Equals(&identity) {
		return nil, nil, InvalidInputError
	}

	var blindedElement ristretto.Point
	blindedElement.ScalarMult(&inputElement, &blind)
	blindBytes, err := blind.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode blind: %v", err)
	}
	blindedElementBytes, err := blindedElement.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode blinded element: %v", err)
	}
	return blindBytes, blindedElementBytes, nil
}

// BlindMarshaledPoint blinds an already-marshaled Ristretto point (e.g., a pseudonym)
// This is used when blinding a pseudonym to recover the original BSN.
func BlindMarshaledPoint(marshaledPoint []byte) ([]byte, []byte, error) {
	var point ristretto.Point
	if err := point.UnmarshalBinary(marshaledPoint); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal point: %v", err)
	}

	var identity ristretto.Point
	identity.SetZero()
	if point.Equals(&identity) {
		return nil, nil, InvalidInputError
	}

	var blind ristretto.Scalar
	blind.Rand()

	var blindedPoint ristretto.Point
	blindedPoint.ScalarMult(&point, &blind)

	blindBytes, err := blind.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode blind: %v", err)
	}
	blindedPointBytes, err := blindedPoint.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode blinded point: %v", err)
	}
	return blindBytes, blindedPointBytes, nil
}

func Unembed(m ristretto.Point) []byte {
	res := [16]byte{}
	em := m.Lizard()
	// Copy only the number of bytes that were originally embedded
	copy(res[:], em[:])
	return res[:]
}

func NewInput(msg string) []byte {
	em := [16]byte{}
	copy(em[:], []byte(msg))
	return em[:]
}

func Embed(msg []byte) ristretto.Point {
	em := [16]byte{}
	copy(em[:], msg)

	m := ristretto.Point{}
	m.SetLizard(&em)
	return m
}

// BlindEvaluate:
// Input:
//
//	Scalar skS
//	Element blindedElement
//
// Output:
//
//	Element evaluatedElement
//
// def BlindEvaluate(skS, blindedElement):
//
//	evaluatedElement = skS * blindedElement
//	return evaluatedElement
func BlindEvaluate(skS ristretto.Scalar, encodedBlindedElement []byte) ([]byte, error) {
	var blindedElement ristretto.Point
	if err := blindedElement.UnmarshalBinary(encodedBlindedElement); err != nil {
		return nil, fmt.Errorf("failed to decode blinded element: %v", err)
	}
	var evaluatedElement ristretto.Point
	evaluatedElement.ScalarMult(&blindedElement, &skS)
	res, err := evaluatedElement.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode evaluated element: %v", err)
	}
	return res, nil
}

func KeyForOrgID(orgID string) ristretto.Scalar {
	var skS ristretto.Scalar
	skS.Derive([]byte("org-key:" + orgID))
	return skS
}

// Unblind:
// Input:
//
//   PrivateInput input
//   Scalar blind
//   Element evaluatedElement
//
// Output:
//
//   unblindedElement
//
// Parameters:
//
//   Group G
//
// def Unblind(input, blind, evaluatedElement):
//   N = G.ScalarInverse(blind) * evaluatedElement
//   unblindedElement = G.SerializeElement(N)
//
//   return unblindedElement

func Unblind(encodedBlind, encodedEvaluatedElement []byte) (ristretto.Point, error) {
	var blind ristretto.Scalar
	if err := blind.UnmarshalBinary(encodedBlind); err != nil {
		return ristretto.Point{}, fmt.Errorf("failed to decode blind: %v", err)
	}
	var evaluatedElement ristretto.Point
	if err := evaluatedElement.UnmarshalBinary(encodedEvaluatedElement); err != nil {
		return ristretto.Point{}, fmt.Errorf("failed to decode evaluated element: %v", err)
	}
	var blindInv ristretto.Scalar
	blindInv.Inverse(&blind)

	var unblindedElement ristretto.Point
	unblindedElement.ScalarMult(&evaluatedElement, &blindInv)

	return unblindedElement, nil
}

func Unevaluate(skS ristretto.Scalar, encodedBlindedElement []byte) ([]byte, error) {
	var blindedElement ristretto.Point
	if err := blindedElement.UnmarshalBinary(encodedBlindedElement); err != nil {
		return nil, fmt.Errorf("failed to decode unblinded element: %v", err)
	}
	var skSInv ristretto.Scalar
	skSInv.Inverse(&skS)

	var originalBlindedElement ristretto.Point
	originalBlindedElement.ScalarMult(&blindedElement, &skSInv)
	res, err := originalBlindedElement.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode original blinded element: %v", err)
	}
	return res, nil
}
