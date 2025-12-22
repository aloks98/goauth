// Package goauth provides stateful authentication and authorization for Go applications.
//
// GoAuth supports two modes:
//   - Simple Mode: JWT tokens, refresh token rotation, password hashing, and API keys
//   - Full Mode: Everything above plus user-level RBAC with role templates
//
// Basic usage:
//
//	auth, err := goauth.New[MyClaims](
//	    goauth.WithSecret("your-256-bit-secret"),
//	    goauth.WithStore(memoryStore),
//	)
//
// With RBAC:
//
//	auth, err := goauth.New[MyClaims](
//	    goauth.WithSecret("your-256-bit-secret"),
//	    goauth.WithStore(postgresStore),
//	    goauth.WithRBACFromFile("./permissions.yaml"),
//	)
package goauth

import (
	"context"
	"fmt"
	"sync"

	"github.com/aloks98/goauth/password"
	"github.com/aloks98/goauth/store"
)

// Auth is the main entry point for goauth functionality.
// T is the custom claims type that must embed StandardClaims.
type Auth[T Claims] struct {
	config *Config
	store  store.Store

	// These will be initialized in later phases
	// tokenService *token.Service
	// rbac         *rbac.RBAC
	// apiKeyMgr    *apikey.Manager
	hasher password.Hasher
	// rateLimiter  ratelimit.Limiter
	// cleanup      *cleanup.Worker

	// mu protects concurrent access
	mu sync.RWMutex

	// closed indicates if the Auth instance has been closed
	closed bool
}

// New creates a new Auth instance with the given options.
// At minimum, WithSecret and WithStore must be provided.
func New[T Claims](opts ...Option) (*Auth[T], error) {
	// Start with default config
	cfg := NewConfig()

	// Apply all options to config
	for _, opt := range opts {
		opt(cfg)
	}

	// Extract special options from registries
	s := getStoreFromRegistry(cfg)
	h := getHasherFromRegistry(cfg)
	_ = getRateLimiterFromRegistry(cfg) // Will be used in Phase 7

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Store is required
	if s == nil {
		return nil, ErrStoreRequired
	}

	// Create the Auth instance
	auth := &Auth[T]{
		config: cfg,
		store:  s,
		hasher: h,
	}

	// Auto-migrate if enabled
	if cfg.AutoMigrate {
		if err := auth.store.Migrate(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to migrate database: %w", err)
		}
	}

	// TODO: Initialize token service (Phase 2)
	// TODO: Initialize RBAC if enabled (Phase 4)
	// TODO: Initialize API key manager (Phase 3)
	// TODO: Start cleanup worker if enabled (Phase 7)
	// TODO: Sync role templates if enabled (Phase 4)

	return auth, nil
}

// WithStore sets the data store for tokens and permissions.
// This is a required option.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		// Store in a package-level registry keyed by config pointer
		// This is a bit hacky but necessary given the Option signature
		storeRegistry.Store(c, s)
	}
}

// storeRegistry maps Config pointers to Store instances.
// Used to pass Store through the Option pattern.
var storeRegistry = &sync.Map{}

// getStoreFromRegistry retrieves a store for a config.
func getStoreFromRegistry(c *Config) store.Store {
	if v, ok := storeRegistry.Load(c); ok {
		storeRegistry.Delete(c) // Clean up
		return v.(store.Store)
	}
	return nil
}

// Hasher-related option wrapper
var hasherRegistry = &sync.Map{}

// WithPasswordHasher sets the password hashing algorithm.
func WithPasswordHasher(hasher password.Hasher) Option {
	return func(c *Config) {
		hasherRegistry.Store(c, hasher)
	}
}

// getHasherFromRegistry retrieves a hasher for a config.
func getHasherFromRegistry(c *Config) password.Hasher {
	if v, ok := hasherRegistry.Load(c); ok {
		hasherRegistry.Delete(c) // Clean up
		return v.(password.Hasher)
	}
	return nil
}

// RateLimiter-related option wrapper
var rateLimiterRegistry = &sync.Map{}

// WithRateLimiter configures rate limiting.
func WithRateLimiter(config RateLimitConfig) Option {
	return func(c *Config) {
		rateLimiterRegistry.Store(c, &config)
	}
}

// getRateLimiterFromRegistry retrieves rate limiter config.
func getRateLimiterFromRegistry(c *Config) *RateLimitConfig {
	if v, ok := rateLimiterRegistry.Load(c); ok {
		rateLimiterRegistry.Delete(c) // Clean up
		return v.(*RateLimitConfig)
	}
	return nil
}

// Config returns the current configuration.
// The returned config should not be modified.
func (a *Auth[T]) Config() *Config {
	return a.config
}

// Store returns the underlying store.
func (a *Auth[T]) Store() store.Store {
	return a.store
}

// IsRBACEnabled returns true if RBAC is configured.
func (a *Auth[T]) IsRBACEnabled() bool {
	return a.config.IsRBACEnabled()
}

// Close releases all resources and stops background workers.
// After Close is called, the Auth instance should not be used.
func (a *Auth[T]) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil
	}
	a.closed = true

	// TODO: Stop cleanup worker (Phase 7)

	// Close the store
	if a.store != nil {
		return a.store.Close()
	}

	return nil
}

// Ping verifies the store connection is alive.
func (a *Auth[T]) Ping(ctx context.Context) error {
	return a.store.Ping(ctx)
}
