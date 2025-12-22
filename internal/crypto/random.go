// Package crypto provides cryptographic utilities.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// GenerateRandomBytes generates n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomString generates a random string of the specified byte length.
// The returned string is URL-safe base64 encoded.
func GenerateRandomString(byteLength int) (string, error) {
	b, err := GenerateRandomBytes(byteLength)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateRandomHex generates a random hex string of the specified byte length.
// The returned string will be 2*byteLength characters.
func GenerateRandomHex(byteLength int) (string, error) {
	b, err := GenerateRandomBytes(byteLength)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateID generates a random identifier suitable for use as a JTI or family ID.
// Returns a 32-character hex string (16 bytes of entropy).
func GenerateID() (string, error) {
	return GenerateRandomHex(16)
}

// GenerateAPIKey generates a random API key with the given prefix.
// Format: prefix_randomhex
func GenerateAPIKey(prefix string, byteLength int) (string, error) {
	random, err := GenerateRandomHex(byteLength)
	if err != nil {
		return "", err
	}
	return prefix + "_" + random, nil
}
