// Package password provides password hashing and verification.
package password

// Hasher defines the interface for password hashing algorithms.
type Hasher interface {
	// Hash creates a hash from a password.
	Hash(password string) (string, error)

	// Verify checks if a password matches a hash.
	Verify(password, hash string) (bool, error)

	// NeedsRehash checks if a hash needs to be regenerated.
	// Returns true if the hash was created with different parameters.
	NeedsRehash(hash string) bool
}
