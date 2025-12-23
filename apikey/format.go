package apikey

import (
	"encoding/base64"
	"errors"
	"strings"
)

// formatKey creates the full API key string.
// Format: prefix.base64urlsafe(randomBytes)
// Uses '.' as separator since '_' is a valid base64url character.
func formatKey(prefix string, randomBytes []byte) string {
	encoded := encodeKey(randomBytes)
	return prefix + "." + encoded
}

// encodeKey encodes random bytes to a URL-safe base64 string.
func encodeKey(randomBytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

// parseKey extracts the prefix and random part from an API key.
// Returns the prefix, the raw random bytes as a string, and any error.
func parseKey(rawKey string) (prefix, randomPart string, err error) {
	// Use '.' as separator since it's not a valid base64url character
	// but '_' is (base64url uses A-Z, a-z, 0-9, -, _)
	idx := strings.LastIndex(rawKey, ".")
	if idx == -1 {
		return "", "", errors.New("invalid key format: missing prefix separator")
	}

	prefix = rawKey[:idx]
	encoded := rawKey[idx+1:]

	if prefix == "" || encoded == "" {
		return "", "", errors.New("invalid key format: empty prefix or key")
	}

	// Decode the base64 part
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", errors.New("invalid key format: invalid encoding")
	}

	return prefix, string(decoded), nil
}

// getHint returns the last n characters of a string.
func getHint(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
