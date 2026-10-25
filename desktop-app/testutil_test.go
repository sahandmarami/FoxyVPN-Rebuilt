package main

// Test helpers: Ed25519 keypair generation for minting test keys.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

// ed25519GenerateKey returns (publicB64, privateSeed) — publicB64 in the
// same std-base64 form the client's pubKeys list uses.
func ed25519GenerateKey() (string, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(pub), priv, nil
}
