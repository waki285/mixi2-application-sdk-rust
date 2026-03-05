// Package testutil provides common testing utilities for event handling tests.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// GenerateKeyPair generates an Ed25519 key pair for testing purposes.
func GenerateKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return pub, priv
}

// SignRequest signs a request body with a timestamp using an Ed25519 private key.
// Returns the base64-encoded signature.
func SignRequest(body []byte, timestamp string, privateKey ed25519.PrivateKey) string {
	dataToSign := append(body, []byte(timestamp)...)
	signature := ed25519.Sign(privateKey, dataToSign)
	return base64.StdEncoding.EncodeToString(signature)
}
