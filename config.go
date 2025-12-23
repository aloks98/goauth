package goauth

import (
	"fmt"
	"time"

	"github.com/aloks98/goauth/rbac"
)

// Re-export RBAC types for convenience.
// Users can use goauth.RBACConfig instead of rbac.Config.
type (
	// RBACConfig defines the role-based access control configuration.
	RBACConfig = rbac.Config

	// PermissionGroup groups related permissions together.
	PermissionGroup = rbac.PermissionGroup

	// Permission defines a single permission.
	Permission = rbac.Permission

	// RoleTemplate defines a role template with a set of permissions.
	RoleTemplate = rbac.RoleTemplate
)

// SigningMethod represents the JWT signing algorithm.
type SigningMethod string

const (
	// SigningMethodHS256 uses HMAC-SHA256 for signing (symmetric).
	SigningMethodHS256 SigningMethod = "HS256"

	// SigningMethodHS384 uses HMAC-SHA384 for signing (symmetric).
	SigningMethodHS384 SigningMethod = "HS384"

	// SigningMethodHS512 uses HMAC-SHA512 for signing (symmetric).
	SigningMethodHS512 SigningMethod = "HS512"

	// SigningMethodRS256 uses RSA-SHA256 for signing (asymmetric).
	SigningMethodRS256 SigningMethod = "RS256"

	// SigningMethodRS384 uses RSA-SHA384 for signing (asymmetric).
	SigningMethodRS384 SigningMethod = "RS384"

	// SigningMethodRS512 uses RSA-SHA512 for signing (asymmetric).
	SigningMethodRS512 SigningMethod = "RS512"
)

// Default configuration values.
const (
	DefaultAccessTokenTTL     = 15 * time.Minute
	DefaultRefreshTokenTTL    = 7 * 24 * time.Hour
	DefaultCleanupInterval    = 1 * time.Hour
	DefaultPermissionCacheTTL = 30 * time.Second
	DefaultAPIKeyPrefix       = "sk"
	DefaultAPIKeyLength       = 32
	DefaultTablePrefix        = "auth_"

	// MinSecretLength is the minimum required length for the secret key.
	MinSecretLength = 32
)

// Config holds all configuration for the Auth instance.
type Config struct {
	// Secret is the key used for signing tokens (required for HMAC methods).
	Secret string

	// PrivateKey is the private key for RSA signing (required for RS* methods).
	PrivateKey any

	// PublicKey is the public key for RSA verification (required for RS* methods).
	PublicKey any

	// AccessTokenTTL is how long access tokens are valid.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is how long refresh tokens are valid.
	RefreshTokenTTL time.Duration

	// SigningMethod is the JWT signing algorithm to use.
	SigningMethod SigningMethod

	// TablePrefix is the prefix for database table names.
	TablePrefix string

	// AutoMigrate enables automatic database migration on startup.
	AutoMigrate bool

	// CleanupInterval is how often expired tokens are cleaned up.
	// Set to 0 to disable background cleanup.
	CleanupInterval time.Duration

	// PermissionVersionCheck enables checking if user permissions have changed.
	// When enabled, tokens with outdated permission versions are rejected.
	PermissionVersionCheck bool

	// PermissionCacheTTL is how long permission lookups are cached.
	PermissionCacheTTL time.Duration

	// RoleSyncOnStartup enables syncing role templates to users on startup.
	RoleSyncOnStartup bool

	// APIKeyPrefix is the prefix for generated API keys (e.g., "sk_live").
	APIKeyPrefix string

	// APIKeyLength is the length of the random portion of API keys.
	APIKeyLength int

	// RBACConfig holds the RBAC configuration when enabled.
	RBACConfig *RBACConfig

	// RBACConfigPath is the path to the RBAC configuration file.
	RBACConfigPath string

	// RBACConfigData is raw RBAC configuration data (alternative to file path).
	RBACConfigData []byte
}

// RateLimitConfig defines rate limiting configuration.
type RateLimitConfig struct {
	// Enabled turns rate limiting on/off.
	Enabled bool

	// RequestsPerWindow is the maximum number of requests allowed per window.
	RequestsPerWindow int

	// WindowDuration is the time window for rate limiting.
	WindowDuration time.Duration

	// KeyFunc is a function that returns the rate limit key for a request.
	// Common keys: IP address, user ID, API key prefix.
	KeyFunc func(ctx any) string
}

// NewConfig creates a new Config with default values.
func NewConfig() *Config {
	return &Config{
		AccessTokenTTL:         DefaultAccessTokenTTL,
		RefreshTokenTTL:        DefaultRefreshTokenTTL,
		SigningMethod:          SigningMethodHS256,
		TablePrefix:            DefaultTablePrefix,
		AutoMigrate:            false,
		CleanupInterval:        DefaultCleanupInterval,
		PermissionVersionCheck: true,
		PermissionCacheTTL:     DefaultPermissionCacheTTL,
		RoleSyncOnStartup:      true,
		APIKeyPrefix:           DefaultAPIKeyPrefix,
		APIKeyLength:           DefaultAPIKeyLength,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	// Check signing method and corresponding key requirements
	switch c.SigningMethod {
	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		if c.Secret == "" {
			return fmt.Errorf("%w: secret is required for HMAC signing", ErrConfigInvalid)
		}
		if len(c.Secret) < MinSecretLength {
			return fmt.Errorf("%w: secret must be at least %d characters", ErrConfigInvalid, MinSecretLength)
		}
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		if c.PrivateKey == nil {
			return fmt.Errorf("%w: private key is required for RSA signing", ErrConfigInvalid)
		}
		if c.PublicKey == nil {
			return fmt.Errorf("%w: public key is required for RSA verification", ErrConfigInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported signing method: %s", ErrConfigInvalid, c.SigningMethod)
	}

	// Validate TTL values
	if c.AccessTokenTTL <= 0 {
		return fmt.Errorf("%w: access token TTL must be positive", ErrConfigInvalid)
	}
	if c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("%w: refresh token TTL must be positive", ErrConfigInvalid)
	}
	if c.RefreshTokenTTL <= c.AccessTokenTTL {
		return fmt.Errorf("%w: refresh token TTL must be greater than access token TTL", ErrConfigInvalid)
	}

	// Validate API key settings
	if c.APIKeyLength < 16 {
		return fmt.Errorf("%w: API key length must be at least 16", ErrConfigInvalid)
	}
	if c.APIKeyPrefix == "" {
		return fmt.Errorf("%w: API key prefix cannot be empty", ErrConfigInvalid)
	}

	// Validate cleanup interval if set
	if c.CleanupInterval < 0 {
		return fmt.Errorf("%w: cleanup interval cannot be negative", ErrConfigInvalid)
	}

	return nil
}

// IsRBACEnabled returns true if RBAC is configured.
func (c *Config) IsRBACEnabled() bool {
	return c.RBACConfig != nil || c.RBACConfigPath != "" || len(c.RBACConfigData) > 0
}

// IsHMAC returns true if the signing method is HMAC-based.
func (c *Config) IsHMAC() bool {
	switch c.SigningMethod {
	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		return true
	default:
		return false
	}
}

// IsRSA returns true if the signing method is RSA-based.
func (c *Config) IsRSA() bool {
	switch c.SigningMethod {
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		return true
	default:
		return false
	}
}
