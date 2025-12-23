package password

import (
	"golang.org/x/crypto/bcrypt"
)

// BcryptConfig holds the configuration for bcrypt hashing.
type BcryptConfig struct {
	// Cost is the bcrypt cost factor (4-31).
	// Higher values are more secure but slower.
	Cost int
}

// DefaultBcryptConfig returns secure default parameters for bcrypt.
func DefaultBcryptConfig() *BcryptConfig {
	return &BcryptConfig{
		Cost: 12, // Good balance of security and performance
	}
}

// BcryptHasher implements the Hasher interface using bcrypt.
type BcryptHasher struct {
	config *BcryptConfig
}

// NewBcryptHasher creates a new bcrypt hasher with the given configuration.
// If config is nil, DefaultBcryptConfig is used.
func NewBcryptHasher(config *BcryptConfig) *BcryptHasher {
	if config == nil {
		config = DefaultBcryptConfig()
	}
	// Clamp cost to valid range
	if config.Cost < bcrypt.MinCost {
		config.Cost = bcrypt.MinCost
	}
	if config.Cost > bcrypt.MaxCost {
		config.Cost = bcrypt.MaxCost
	}
	return &BcryptHasher{config: config}
}

// Hash creates a bcrypt hash from a password.
func (h *BcryptHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.config.Cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Verify checks if a password matches a bcrypt hash.
func (h *BcryptHasher) Verify(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// NeedsRehash checks if a hash was created with a different cost.
func (h *BcryptHasher) NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true
	}
	return cost != h.config.Cost
}

// Ensure BcryptHasher implements Hasher.
var _ Hasher = (*BcryptHasher)(nil)
