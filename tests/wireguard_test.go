package tests

import (
	"testing"
	"zarkham/core/vpn"
)

func TestKeyGeneration(t *testing.T) {
	priv, pub, err := vpn.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	if len(priv) != 32 {
		t.Errorf("Private key length mismatch. Expected 32, got %d", len(priv))
	}
	if len(pub) != 32 {
		t.Errorf("Public key length mismatch. Expected 32, got %d", len(pub))
	}

	// Verify pairing (basic check)
	if priv.PublicKey() != pub {
		t.Errorf("Private key does not match public key")
	}
}
