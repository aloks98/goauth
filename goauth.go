// Package goauth provides stateful authentication and authorization for Go applications.
//
// GoAuth supports two modes:
//   - Simple Mode: JWT tokens, refresh token rotation, and API keys
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
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/aloks98/goauth/apikey"
	"github.com/aloks98/goauth/cleanup"
	"github.com/aloks98/goauth/ratelimit"
	"github.com/aloks98/goauth/rbac"
	"github.com/aloks98/goauth/store"
	"github.com/aloks98/goauth/token"
)

// Auth is the main entry point for goauth functionality.
// T is the custom claims type that must embed StandardClaims.
type Auth[T Claims] struct {
	config *Config
	store  store.Store

	// Services
	tokenService  *token.Service
	rbacService   *rbac.Service
	apiKeyService *apikey.Service
	cleanupWorker *cleanup.Worker
	rateLimiter   ratelimit.Limiter

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
	rateLimitCfg := getRateLimiterFromRegistry(cfg)

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
	}

	// Auto-migrate if enabled
	if cfg.AutoMigrate {
		if err := auth.store.Migrate(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to migrate database: %w", err)
		}
	}

	// Initialize token service
	tokenCfg := &token.Config{
		Secret:                 cfg.Secret,
		SigningMethod:          string(cfg.SigningMethod),
		AccessTokenTTL:         cfg.AccessTokenTTL,
		RefreshTokenTTL:        cfg.RefreshTokenTTL,
		PermissionVersionCheck: cfg.PermissionVersionCheck,
		PermissionCacheTTL:     cfg.PermissionCacheTTL,
	}

	// Handle RSA keys if present
	if cfg.PrivateKey != nil {
		if pk, ok := cfg.PrivateKey.(*rsa.PrivateKey); ok {
			tokenCfg.PrivateKey = pk
		}
	}
	if cfg.PublicKey != nil {
		if pk, ok := cfg.PublicKey.(*rsa.PublicKey); ok {
			tokenCfg.PublicKey = pk
		}
	}

	auth.tokenService = token.NewService(tokenCfg, s)

	// Initialize RBAC if enabled
	if cfg.IsRBACEnabled() {
		var rbacCfg *rbac.Config
		var err error

		if cfg.RBACConfig != nil {
			// RBACConfig is now a type alias, use directly
			rbacCfg = cfg.RBACConfig
		} else if cfg.RBACConfigPath != "" {
			rbacCfg, err = rbac.LoadFromFile(cfg.RBACConfigPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load RBAC config: %w", err)
			}
		} else if len(cfg.RBACConfigData) > 0 {
			rbacCfg, err = rbac.LoadFromBytes(cfg.RBACConfigData, ".yaml")
			if err != nil {
				return nil, fmt.Errorf("failed to parse RBAC config: %w", err)
			}
		}

		auth.rbacService, err = rbac.NewService(rbacCfg, s)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize RBAC service: %w", err)
		}

		// Sync role templates if enabled
		if cfg.RoleSyncOnStartup {
			if err := auth.rbacService.SyncRoleTemplates(context.Background()); err != nil {
				return nil, fmt.Errorf("failed to sync role templates: %w", err)
			}
		}
	}

	// Initialize API key service
	apiKeyCfg := &apikey.Config{
		Prefix:    cfg.APIKeyPrefix,
		KeyLength: cfg.APIKeyLength,
	}
	auth.apiKeyService = apikey.NewService(apiKeyCfg, s)

	// Start cleanup worker if enabled
	if cfg.CleanupInterval > 0 {
		cleanupCfg := cleanup.DefaultConfig(s)
		cleanupCfg.Interval = cfg.CleanupInterval
		auth.cleanupWorker = cleanup.NewWorker(cleanupCfg)
		auth.cleanupWorker.Start()
	}

	// Initialize rate limiter if configured
	if rateLimitCfg != nil && rateLimitCfg.Enabled {
		auth.rateLimiter = ratelimit.NewMemoryLimiter(
			rateLimitCfg.RequestsPerWindow,
			rateLimitCfg.WindowDuration,
		)
	}

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

	// Stop cleanup worker
	if a.cleanupWorker != nil {
		a.cleanupWorker.Stop()
	}

	// Close rate limiter
	if a.rateLimiter != nil {
		_ = a.rateLimiter.Close()
	}

	// Close the store
	if a.store != nil {
		return a.store.Close()
	}

	return nil
}

// RateLimiter returns the configured rate limiter, or nil if not configured.
func (a *Auth[T]) RateLimiter() ratelimit.Limiter {
	return a.rateLimiter
}

// Ping verifies the store connection is alive.
func (a *Auth[T]) Ping(ctx context.Context) error {
	return a.store.Ping(ctx)
}

// =============================================================================
// Token Methods
// =============================================================================

// GenerateTokenPair generates a new access/refresh token pair for a user.
func (a *Auth[T]) GenerateTokenPair(ctx context.Context, userID string, customClaims map[string]any) (*token.Pair, error) {
	return a.tokenService.GenerateTokenPair(ctx, userID, customClaims)
}

// ValidateAccessToken validates an access token and returns its claims.
func (a *Auth[T]) ValidateAccessToken(ctx context.Context, tokenString string) (*token.Claims, error) {
	return a.tokenService.ValidateAccessToken(ctx, tokenString)
}

// RefreshTokens validates a refresh token and returns a new token pair.
func (a *Auth[T]) RefreshTokens(ctx context.Context, refreshToken string) (*token.Pair, error) {
	return a.tokenService.RefreshTokens(ctx, refreshToken)
}

// RevokeAccessToken adds an access token to the blacklist.
func (a *Auth[T]) RevokeAccessToken(ctx context.Context, tokenString string) error {
	return a.tokenService.RevokeAccessToken(ctx, tokenString)
}

// RevokeRefreshToken revokes a specific refresh token by JTI.
func (a *Auth[T]) RevokeRefreshToken(ctx context.Context, jti string) error {
	return a.tokenService.RevokeRefreshToken(ctx, jti)
}

// RevokeTokenFamily revokes all tokens in a family.
func (a *Auth[T]) RevokeTokenFamily(ctx context.Context, familyID string) error {
	return a.tokenService.RevokeTokenFamily(ctx, familyID)
}

// RevokeAllUserTokens revokes all tokens for a user.
func (a *Auth[T]) RevokeAllUserTokens(ctx context.Context, userID string) error {
	return a.tokenService.RevokeAllUserTokens(ctx, userID)
}

// =============================================================================
// API Key Methods
// =============================================================================

// CreateAPIKey generates a new API key for a user.
// The raw key is only returned once and cannot be retrieved later.
func (a *Auth[T]) CreateAPIKey(ctx context.Context, userID string, opts *apikey.CreateKeyOptions) (*apikey.CreateKeyResult, error) {
	return a.apiKeyService.CreateKey(ctx, userID, opts)
}

// ValidateAPIKey validates an API key and returns its metadata.
func (a *Auth[T]) ValidateAPIKey(ctx context.Context, rawKey string) (*apikey.ValidateResult, error) {
	return a.apiKeyService.ValidateKey(ctx, rawKey)
}

// ValidateAPIKeyWithScope validates an API key and checks for a required scope.
func (a *Auth[T]) ValidateAPIKeyWithScope(ctx context.Context, rawKey, requiredScope string) (*apikey.ValidateResult, error) {
	return a.apiKeyService.ValidateKeyWithScope(ctx, rawKey, requiredScope)
}

// RevokeAPIKey revokes an API key by ID.
func (a *Auth[T]) RevokeAPIKey(ctx context.Context, id string) error {
	return a.apiKeyService.RevokeKey(ctx, id)
}

// ListAPIKeys returns all API keys for a user.
func (a *Auth[T]) ListAPIKeys(ctx context.Context, userID string) ([]*store.APIKey, error) {
	return a.apiKeyService.ListKeys(ctx, userID)
}

// =============================================================================
// RBAC Methods
// =============================================================================

// AssignRole assigns a role template to a user.
// This copies the role's permissions to the user.
func (a *Auth[T]) AssignRole(ctx context.Context, userID, roleKey string) error {
	if !a.IsRBACEnabled() {
		return ErrRBACNotEnabled
	}
	return a.rbacService.AssignRole(ctx, userID, roleKey)
}

// AddPermissions adds permissions to a user.
func (a *Auth[T]) AddPermissions(ctx context.Context, userID string, permissions []string) error {
	if !a.IsRBACEnabled() {
		return ErrRBACNotEnabled
	}
	return a.rbacService.AddPermissions(ctx, userID, permissions)
}

// RemovePermissions removes permissions from a user.
func (a *Auth[T]) RemovePermissions(ctx context.Context, userID string, permissions []string) error {
	if !a.IsRBACEnabled() {
		return ErrRBACNotEnabled
	}
	return a.rbacService.RemovePermissions(ctx, userID, permissions)
}

// SetPermissions sets a user's permissions directly.
func (a *Auth[T]) SetPermissions(ctx context.Context, userID string, permissions []string) error {
	if !a.IsRBACEnabled() {
		return ErrRBACNotEnabled
	}
	return a.rbacService.SetPermissions(ctx, userID, permissions)
}

// ResetToRole resets a user's permissions to match their base role.
func (a *Auth[T]) ResetToRole(ctx context.Context, userID string) error {
	if !a.IsRBACEnabled() {
		return ErrRBACNotEnabled
	}
	return a.rbacService.ResetToRole(ctx, userID)
}

// GetUserPermissions returns a user's permissions.
func (a *Auth[T]) GetUserPermissions(ctx context.Context, userID string) (*store.UserPermissions, error) {
	if !a.IsRBACEnabled() {
		return nil, ErrRBACNotEnabled
	}
	return a.rbacService.GetUserPermissions(ctx, userID)
}

// HasPermission checks if a user has a specific permission.
func (a *Auth[T]) HasPermission(ctx context.Context, userID, permission string) (bool, error) {
	if !a.IsRBACEnabled() {
		return false, ErrRBACNotEnabled
	}
	return a.rbacService.HasPermission(ctx, userID, permission)
}

// HasAllPermissions checks if a user has all specified permissions.
func (a *Auth[T]) HasAllPermissions(ctx context.Context, userID string, permissions []string) (bool, error) {
	if !a.IsRBACEnabled() {
		return false, ErrRBACNotEnabled
	}
	return a.rbacService.HasAllPermissions(ctx, userID, permissions)
}

// HasAnyPermission checks if a user has any of the specified permissions.
func (a *Auth[T]) HasAnyPermission(ctx context.Context, userID string, permissions []string) (bool, error) {
	if !a.IsRBACEnabled() {
		return false, ErrRBACNotEnabled
	}
	return a.rbacService.HasAnyPermission(ctx, userID, permissions)
}

// RequirePermission returns an error if the user doesn't have the permission.
func (a *Auth[T]) RequirePermission(ctx context.Context, userID, permission string) error {
	if !a.IsRBACEnabled() {
		return ErrRBACNotEnabled
	}
	return a.rbacService.RequirePermission(ctx, userID, permission)
}

// GetAllRoles returns all defined role templates.
func (a *Auth[T]) GetAllRoles() []RoleTemplate {
	if !a.IsRBACEnabled() {
		return nil
	}
	return a.rbacService.GetAllRoles()
}

// GetAllPermissionGroups returns all defined permission groups.
func (a *Auth[T]) GetAllPermissionGroups() []PermissionGroup {
	if !a.IsRBACEnabled() {
		return nil
	}
	return a.rbacService.GetAllPermissionGroups()
}
