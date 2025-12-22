// Package store defines the storage interface for goauth.
package store

import (
	"context"
)

// Store defines the interface for goauth data persistence.
// All methods should be safe for concurrent use.
type Store interface {
	// Lifecycle methods

	// Close releases any resources held by the store.
	Close() error

	// Ping verifies the store connection is alive.
	Ping(ctx context.Context) error

	// Migrate creates or updates the database schema.
	Migrate(ctx context.Context) error

	// Refresh Token methods

	// SaveRefreshToken persists a new refresh token.
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error

	// GetRefreshToken retrieves a refresh token by its JTI.
	GetRefreshToken(ctx context.Context, jti string) (*RefreshToken, error)

	// RevokeRefreshToken marks a refresh token as revoked.
	// replacedBy is the JTI of the token that replaced this one (for rotation).
	RevokeRefreshToken(ctx context.Context, jti string, replacedBy string) error

	// RevokeTokenFamily revokes all tokens in a family (for theft detection).
	RevokeTokenFamily(ctx context.Context, familyID string) error

	// RevokeAllUserRefreshTokens revokes all refresh tokens for a user.
	RevokeAllUserRefreshTokens(ctx context.Context, userID string) error

	// DeleteExpiredRefreshTokens removes expired refresh tokens.
	// Returns the number of tokens deleted.
	DeleteExpiredRefreshTokens(ctx context.Context) (int64, error)

	// Access Token Blacklist methods

	// AddToBlacklist adds an access token JTI to the blacklist.
	AddToBlacklist(ctx context.Context, jti string, expiresAt int64) error

	// IsBlacklisted checks if an access token JTI is blacklisted.
	IsBlacklisted(ctx context.Context, jti string) (bool, error)

	// DeleteExpiredBlacklistEntries removes expired blacklist entries.
	// Returns the number of entries deleted.
	DeleteExpiredBlacklistEntries(ctx context.Context) (int64, error)

	// User Permissions methods (for RBAC)

	// GetUserPermissions retrieves permissions for a user.
	// Returns nil if user has no permissions record.
	GetUserPermissions(ctx context.Context, userID string) (*UserPermissions, error)

	// SaveUserPermissions creates or updates user permissions.
	SaveUserPermissions(ctx context.Context, perms *UserPermissions) error

	// DeleteUserPermissions removes a user's permission record.
	DeleteUserPermissions(ctx context.Context, userID string) error

	// UpdateUsersWithRole updates all users with a specific role label.
	// Used for role template sync.
	// Returns the number of users updated.
	UpdateUsersWithRole(ctx context.Context, roleLabel string, permissions []string, newVersion int) (int64, error)

	// Role Template methods

	// GetRoleTemplates retrieves all stored role templates.
	GetRoleTemplates(ctx context.Context) (map[string]*StoredRoleTemplate, error)

	// SaveRoleTemplate saves a role template snapshot.
	SaveRoleTemplate(ctx context.Context, template *StoredRoleTemplate) error

	// API Key methods

	// SaveAPIKey persists a new API key.
	SaveAPIKey(ctx context.Context, key *APIKey) error

	// GetAPIKeyByHash retrieves an API key by its prefix and hash.
	GetAPIKeyByHash(ctx context.Context, prefix string, keyHash string) (*APIKey, error)

	// GetAPIKeysByUser retrieves all API keys for a user.
	GetAPIKeysByUser(ctx context.Context, userID string) ([]*APIKey, error)

	// RevokeAPIKey marks an API key as revoked.
	RevokeAPIKey(ctx context.Context, id string) error

	// DeleteExpiredAPIKeys removes expired API keys.
	// Returns the number of keys deleted.
	DeleteExpiredAPIKeys(ctx context.Context) (int64, error)
}
