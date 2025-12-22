// Package hash provides hashing utilities.
package hash

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// SHA256 computes the SHA256 hash of the input and returns it as a hex string.
func SHA256(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// SHA256Bytes computes the SHA256 hash of the input and returns the raw bytes.
func SHA256Bytes(input string) []byte {
	h := sha256.Sum256([]byte(input))
	return h[:]
}

// ConstantTimeCompare compares two strings in constant time.
// Returns true if they are equal.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ConstantTimeCompareBytes compares two byte slices in constant time.
// Returns true if they are equal.
func ConstantTimeCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
