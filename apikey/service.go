// Package apikey provides API key generation and management.
package apikey

import (
	"context"
	"errors"
	"time"

	"github.com/aloks98/goauth/internal/crypto"
	"github.com/aloks98/goauth/internal/hash"
	"github.com/aloks98/goauth/store"
)

// Errors returned by the API key service.
var (
	// ErrKeyInvalid indicates the API key is invalid or not found.
	ErrKeyInvalid = errors.New("api key is invalid")

	// ErrKeyRevoked indicates the API key has been revoked.
	ErrKeyRevoked = errors.New("api key has been revoked")

	// ErrKeyExpired indicates the API key has expired.
	ErrKeyExpired = errors.New("api key has expired")

	// ErrScopeNotAllowed indicates the key doesn't have the required scope.
	ErrScopeNotAllowed = errors.New("api key scope not allowed")
)

// Config holds configuration for the API key service.
type Config struct {
	// Prefix is prepended to all generated keys (e.g., "sk_live", "sk_test").
	Prefix string

	// KeyLength is the length of the random part in bytes.
	// Default is 32, resulting in ~43 base64 characters.
	KeyLength int

	// HintLength is how many characters of the key to show as a hint.
	// Default is 4.
	HintLength int

	// DefaultTTL is the default expiration time for new keys.
	// Zero means no expiration.
	DefaultTTL time.Duration
}

// DefaultConfig returns a default configuration for the API key service.
func DefaultConfig() *Config {
	return &Config{
		Prefix:     "sk",
		KeyLength:  32,
		HintLength: 4,
		DefaultTTL: 0, // No expiration by default
	}
}

// Service handles API key generation and validation.
type Service struct {
	config *Config
	store  store.Store
}

// NewService creates a new API key service.
func NewService(cfg *Config, s store.Store) *Service {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.KeyLength == 0 {
		cfg.KeyLength = 32
	}
	if cfg.HintLength == 0 {
		cfg.HintLength = 4
	}
	return &Service{
		config: cfg,
		store:  s,
	}
}

// CreateKeyResult contains the result of creating an API key.
// The RawKey is only available at creation time and cannot be retrieved later.
type CreateKeyResult struct {
	// ID is the unique identifier for management.
	ID string

	// RawKey is the full API key (only shown once!).
	RawKey string

	// Prefix is the key prefix (e.g., "sk_live").
	Prefix string

	// Hint is the last few characters for identification.
	Hint string

	// Name is the human-readable name.
	Name string

	// ExpiresAt is when the key expires (nil = never).
	ExpiresAt *time.Time
}

// CreateKeyOptions holds options for creating an API key.
type CreateKeyOptions struct {
	// Name is a human-readable identifier for the key.
	Name string

	// Scopes limits the key to specific permissions (nil = all permissions).
	Scopes []string

	// ExpiresAt sets a custom expiration (nil = use default TTL).
	ExpiresAt *time.Time

	// TTL sets the key to expire after this duration (overridden by ExpiresAt).
	TTL time.Duration
}

// CreateKey generates a new API key for a user.
// The raw key is only returned once and cannot be retrieved later.
func (s *Service) CreateKey(ctx context.Context, userID string, opts *CreateKeyOptions) (*CreateKeyResult, error) {
	if opts == nil {
		opts = &CreateKeyOptions{}
	}

	// Generate unique ID
	id, err := crypto.GenerateID()
	if err != nil {
		return nil, err
	}

	// Generate random key bytes
	randomBytes, err := crypto.GenerateRandomBytes(s.config.KeyLength)
	if err != nil {
		return nil, err
	}

	// Create the full key: prefix_randompart
	rawKey := formatKey(s.config.Prefix, randomBytes)

	// Hash for storage (only hash the random part)
	keyHash := hash.SHA256(string(randomBytes))

	// Get the hint (last N characters of the random part)
	randomStr := encodeKey(randomBytes)
	hint := getHint(randomStr, s.config.HintLength)

	// Determine expiration
	var expiresAt *time.Time
	if opts.ExpiresAt != nil {
		expiresAt = opts.ExpiresAt
	} else if opts.TTL > 0 {
		t := time.Now().Add(opts.TTL)
		expiresAt = &t
	} else if s.config.DefaultTTL > 0 {
		t := time.Now().Add(s.config.DefaultTTL)
		expiresAt = &t
	}

	// Create the API key record
	apiKey := &store.APIKey{
		ID:        id,
		UserID:    userID,
		Name:      opts.Name,
		Prefix:    s.config.Prefix,
		KeyHash:   keyHash,
		Hint:      hint,
		Scopes:    opts.Scopes,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	// Store the key
	if err := s.store.SaveAPIKey(ctx, apiKey); err != nil {
		return nil, err
	}

	return &CreateKeyResult{
		ID:        id,
		RawKey:    rawKey,
		Prefix:    s.config.Prefix,
		Hint:      hint,
		Name:      opts.Name,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateResult contains the result of validating an API key.
type ValidateResult struct {
	// Key is the stored API key information.
	Key *store.APIKey

	// UserID is the user who owns the key.
	UserID string
}

// ValidateKey validates an API key and returns its metadata.
func (s *Service) ValidateKey(ctx context.Context, rawKey string) (*ValidateResult, error) {
	// Parse the key
	prefix, randomPart, err := parseKey(rawKey)
	if err != nil {
		return nil, ErrKeyInvalid
	}

	// Hash the random part
	keyHash := hash.SHA256(randomPart)

	// Look up the key
	apiKey, err := s.store.GetAPIKeyByHash(ctx, prefix, keyHash)
	if err != nil {
		return nil, err
	}
	if apiKey == nil {
		return nil, ErrKeyInvalid
	}

	// Check if revoked
	if apiKey.IsRevoked() {
		return nil, ErrKeyRevoked
	}

	// Check if expired
	if apiKey.IsExpired() {
		return nil, ErrKeyExpired
	}

	return &ValidateResult{
		Key:    apiKey,
		UserID: apiKey.UserID,
	}, nil
}

// ValidateKeyWithScope validates an API key and checks for a required scope.
func (s *Service) ValidateKeyWithScope(ctx context.Context, rawKey string, requiredScope string) (*ValidateResult, error) {
	result, err := s.ValidateKey(ctx, rawKey)
	if err != nil {
		return nil, err
	}

	if !result.Key.HasScope(requiredScope) {
		return nil, ErrScopeNotAllowed
	}

	return result, nil
}

// RevokeKey revokes an API key by ID.
func (s *Service) RevokeKey(ctx context.Context, id string) error {
	return s.store.RevokeAPIKey(ctx, id)
}

// ListKeys returns all API keys for a user.
// Note: Keys are returned without the raw key (it's never stored).
func (s *Service) ListKeys(ctx context.Context, userID string) ([]*store.APIKey, error) {
	return s.store.GetAPIKeysByUser(ctx, userID)
}

// CleanupExpired removes expired API keys from storage.
func (s *Service) CleanupExpired(ctx context.Context) (int64, error) {
	return s.store.DeleteExpiredAPIKeys(ctx)
}
