package goauth

import (
	"os"
	"time"
)

// Option is a function that modifies the configuration.
type Option func(*Config)

// WithSecret sets the secret key for HMAC signing.
// The secret must be at least 32 characters long.
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.Secret = secret
	}
}

// WithRBACFromFile loads RBAC configuration from a YAML or JSON file.
func WithRBACFromFile(path string) Option {
	return func(c *Config) {
		c.RBACConfigPath = path
	}
}

// WithRBACFromBytes loads RBAC configuration from raw bytes.
func WithRBACFromBytes(data []byte) Option {
	return func(c *Config) {
		c.RBACConfigData = data
	}
}

// WithRBACFromEnv loads RBAC configuration from the GOAUTH_RBAC_CONFIG environment variable.
func WithRBACFromEnv() Option {
	return func(c *Config) {
		if data := os.Getenv("GOAUTH_RBAC_CONFIG"); data != "" {
			c.RBACConfigData = []byte(data)
		}
	}
}

// WithAccessTokenTTL sets the access token time-to-live.
func WithAccessTokenTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.AccessTokenTTL = ttl
	}
}

// WithRefreshTokenTTL sets the refresh token time-to-live.
func WithRefreshTokenTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.RefreshTokenTTL = ttl
	}
}

// WithSigningMethod sets the JWT signing algorithm.
func WithSigningMethod(method SigningMethod) Option {
	return func(c *Config) {
		c.SigningMethod = method
	}
}

// WithKeyPair sets the RSA key pair for RS* signing methods.
func WithKeyPair(privateKey, publicKey any) Option {
	return func(c *Config) {
		c.PrivateKey = privateKey
		c.PublicKey = publicKey
	}
}

// WithTablePrefix sets the prefix for database table names.
func WithTablePrefix(prefix string) Option {
	return func(c *Config) {
		c.TablePrefix = prefix
	}
}

// WithAutoMigrate enables or disables automatic database migration.
func WithAutoMigrate(enabled bool) Option {
	return func(c *Config) {
		c.AutoMigrate = enabled
	}
}

// WithCleanupInterval sets how often expired tokens are cleaned up.
// Set to 0 to disable background cleanup.
func WithCleanupInterval(interval time.Duration) Option {
	return func(c *Config) {
		c.CleanupInterval = interval
	}
}

// WithPermissionVersionCheck enables or disables permission version checking.
// When enabled, tokens with outdated permission versions are rejected.
func WithPermissionVersionCheck(enabled bool) Option {
	return func(c *Config) {
		c.PermissionVersionCheck = enabled
	}
}

// WithPermissionCacheTTL sets how long permission lookups are cached.
func WithPermissionCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.PermissionCacheTTL = ttl
	}
}

// WithRoleSyncOnStartup enables or disables role template sync on startup.
func WithRoleSyncOnStartup(enabled bool) Option {
	return func(c *Config) {
		c.RoleSyncOnStartup = enabled
	}
}

// WithAPIKeyPrefix sets the prefix for generated API keys.
func WithAPIKeyPrefix(prefix string) Option {
	return func(c *Config) {
		c.APIKeyPrefix = prefix
	}
}

// WithAPIKeyLength sets the length of the random portion of API keys.
func WithAPIKeyLength(length int) Option {
	return func(c *Config) {
		c.APIKeyLength = length
	}
}
