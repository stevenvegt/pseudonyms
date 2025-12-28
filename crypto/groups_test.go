package crypto

import (
	"bytes"
	"testing"

	"github.com/bwesterb/go-ristretto"
)

func TestE2eBlinding(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		expectErr bool
	}{
		{
			name:      "normal input",
			input:     NewInput("test input"),
			expectErr: false,
		},
		{
			name:      "empty input",
			input:     NewInput(""),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			blind, blindedElement, err := Blind(tt.input)
			if (err != nil) != tt.expectErr {
				t.Fatalf("expected error: %v, got: %v", tt.expectErr, err)
			}
			if tt.expectErr {
				return
			}

			unblinded, err := Unblind(blind, blindedElement)
			if err != nil {
				t.Fatalf("unblinding failed: %v", err)
			}

			// Verify that the unblinded element matches the original input
			if !bytes.Equal(tt.input, Unembed(unblinded)) {
				t.Fatalf("unblinded input does not match original input: got %v, want %v", unblinded, tt.input)
			}
		})
	}
}

func TestFoo(t *testing.T) {
	t.Run("blinding and unblinding", func(t *testing.T) {
		input := NewInput("bsn:1234567890")
		blind, blindedElement, err := Blind(input)
		if err != nil {
			t.Fatalf("blinding failed: %v", err)
		}

		unblindedElement, err := Unblind(blind, blindedElement)
		if err != nil {
			t.Fatalf("unblinding failed: %v", err)
		}

		if !bytes.Equal(Unembed(unblindedElement), input) {
			t.Fatalf("unblinded input does not match original input: got %v, want %v", Unembed(unblindedElement), input)
		}
	})

	t.Run("Ristretto marshal/unmarshal", func(t *testing.T) {
		p := ristretto.Point{}
		p.Rand()

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var p2 ristretto.Point
		if err := p2.UnmarshalBinary(data); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if !p.Equals(&p2) {
			t.Fatalf("points do not match after marshal/unmarshal")
		}
	})

	t.Run("blind evaluation", func(t *testing.T) {
		input := NewInput("bsn:1234567890")
		key := KeyForOrgID("test-org")
		inputElement := Embed(input)
		inputPointBytes, _ := inputElement.MarshalBinary()
		evaluatedEl, err := BlindEvaluate(key, inputPointBytes)
		if err != nil {
			t.Fatalf("blind evaluation failed: %v", err)
		}

		unEvaluatedEl, err := Unevaluate(key, evaluatedEl)
		if err != nil {
			t.Fatalf("unevaluation failed: %v", err)
		}

		var unEvaluatedPoint ristretto.Point
		if err := unEvaluatedPoint.UnmarshalBinary(unEvaluatedEl); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if !bytes.Equal(Unembed(unEvaluatedPoint), input) {
			t.Fatalf("unevaluated input does not match original input: got %v, want %v", Unembed(unEvaluatedPoint), input)
		}
	})
}

func TestPseudoFlow(t *testing.T) {
	// Simulate a pseudo end-to-end flow
	// 1. Client blinds input
	input := NewInput("bsn:1234567890")
	blind, blindedElement, err := Blind(input)
	if err != nil {
		t.Fatalf("blinding failed: %v", err)
	}

	// 2. Server evaluates blinded element with its secret key
	skS := ristretto.Scalar{}
	skS.Rand()
	evaluatedElement, err := BlindEvaluate(skS, blindedElement)
	if err != nil {
		t.Fatalf("blind evaluation failed: %v", err)
	}

	// 3. Client unblinds the evaluated element
	unblindedElement, err := Unblind(blind, evaluatedElement)
	if err != nil {
		t.Fatalf("unblinding failed: %v", err)
	}

	// Verify that the final output is not the same as the original input
	if bytes.Equal(Unembed(unblindedElement), input) {
		t.Fatalf("final output should not match original input")
	}

	// verify that the blinded operation results in the same value as direct evaluation
	var directEvaluatedElement ristretto.Point
	inputElement := Embed(input)
	directEvaluatedElement.ScalarMult(&inputElement, &skS)
	if !unblindedElement.Equals(&directEvaluatedElement) {
		t.Fatalf("blinded evaluation does not match direct evaluation")
	}
	t.Skip("continue with unevaluation test")

	unevaluatedElement, err := Unevaluate(skS, evaluatedElement)
	if err != nil {
		t.Fatalf("unevaluation failed: %v", err)
	}

	unblindedUnevaluatedElement, err := Unblind(blind, unevaluatedElement)
	if err != nil {
		t.Fatalf("unblinding failed: %v", err)
	}
	if !bytes.Equal(Unembed(unblindedUnevaluatedElement), input) {
		t.Fatalf("unblinding does not match original input")
	}
}
