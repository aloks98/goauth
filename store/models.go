package store

import (
	"time"
)

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	// ID is the unique identifier (JTI) for the token.
	ID string `db:"id" json:"id"`

	// UserID is the user this token belongs to.
	UserID string `db:"user_id" json:"user_id"`

	// FamilyID groups related tokens for rotation tracking.
	// All tokens in a rotation chain share the same family ID.
	FamilyID string `db:"family_id" json:"family_id"`

	// TokenHash is the SHA256 hash of the token value.
	// The raw token is never stored.
	TokenHash string `db:"token_hash" json:"token_hash"`

	// IssuedAt is when the token was created.
	IssuedAt time.Time `db:"issued_at" json:"issued_at"`

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`

	// RevokedAt is when the token was revoked (nil if active).
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`

	// ReplacedBy is the JTI of the token that replaced this one.
	// Set during token rotation.
	ReplacedBy *string `db:"replaced_by" json:"replaced_by,omitempty"`
}

// IsRevoked returns true if the token has been revoked.
func (t *RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsExpired returns true if the token has expired.
func (t *RefreshToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid returns true if the token is neither revoked nor expired.
func (t *RefreshToken) IsValid() bool {
	return !t.IsRevoked() && !t.IsExpired()
}

// BlacklistEntry represents a blacklisted access token.
type BlacklistEntry struct {
	// JTI is the token identifier.
	JTI string `db:"jti" json:"jti"`

	// ExpiresAt is when this entry can be removed.
	// Should match the original token's expiration.
	ExpiresAt int64 `db:"expires_at" json:"expires_at"`

	// CreatedAt is when the token was blacklisted.
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// UserPermissions represents a user's permission record.
type UserPermissions struct {
	// UserID is the unique user identifier.
	UserID string `db:"user_id" json:"user_id"`

	// RoleLabel indicates the assigned role ("admin", "editor", "custom", etc.).
	// "custom" means permissions were modified from the base role.
	RoleLabel string `db:"role_label" json:"role_label"`

	// BaseRole is the original role template that was assigned.
	// Used for resetting to template defaults.
	BaseRole string `db:"base_role" json:"base_role"`

	// Permissions is the list of permission keys.
	Permissions []string `db:"permissions" json:"permissions"`

	// PermissionVersion is incremented when permissions change.
	// Tokens with old versions are rejected.
	PermissionVersion int `db:"permission_version" json:"permission_version"`

	// UpdatedAt is when permissions were last modified.
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// HasPermission checks if the user has a specific permission.
// Supports wildcard matching.
func (u *UserPermissions) HasPermission(required string) bool {
	for _, p := range u.Permissions {
		if matchPermission(p, required) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the user has all specified permissions.
func (u *UserPermissions) HasAllPermissions(required []string) bool {
	for _, r := range required {
		if !u.HasPermission(r) {
			return false
		}
	}
	return true
}

// HasAnyPermission checks if the user has any of the specified permissions.
func (u *UserPermissions) HasAnyPermission(required []string) bool {
	for _, r := range required {
		if u.HasPermission(r) {
			return true
		}
	}
	return false
}

// matchPermission checks if a permission matches a required permission.
// Supports wildcards: "resource:*" matches "resource:read", "*:read" matches "monitors:read", "*" matches all.
func matchPermission(have, want string) bool {
	if have == "*" {
		return true
	}
	if have == want {
		return true
	}

	// Check for wildcard patterns
	haveResource, haveAction := splitPermission(have)
	wantResource, wantAction := splitPermission(want)

	if haveResource == "*" && haveAction == wantAction {
		return true
	}
	if haveAction == "*" && haveResource == wantResource {
		return true
	}

	return false
}

// splitPermission splits a permission into resource and action parts.
func splitPermission(perm string) (resource, action string) {
	for i := 0; i < len(perm); i++ {
		if perm[i] == ':' {
			return perm[:i], perm[i+1:]
		}
	}
	return perm, ""
}

// StoredRoleTemplate represents a role template stored in the database.
// Used to track changes for sync.
type StoredRoleTemplate struct {
	// Key is the unique role identifier.
	Key string `db:"key" json:"key"`

	// Name is the human-readable role name.
	Name string `db:"name" json:"name"`

	// Description explains the role's purpose.
	Description string `db:"description" json:"description"`

	// Permissions is the list of permission keys.
	Permissions []string `db:"permissions" json:"permissions"`

	// PermissionHash is a hash of the sorted permissions for change detection.
	PermissionHash string `db:"permission_hash" json:"permission_hash"`

	// Version is incremented when the template changes.
	Version int `db:"version" json:"version"`

	// UpdatedAt is when the template was last modified.
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// APIKey represents a stored API key.
type APIKey struct {
	// ID is the unique identifier for management.
	ID string `db:"id" json:"id"`

	// UserID is the user this key belongs to.
	UserID string `db:"user_id" json:"user_id"`

	// Name is a human-readable identifier for the key.
	Name string `db:"name" json:"name"`

	// Prefix is the visible prefix (e.g., "sk_live").
	Prefix string `db:"prefix" json:"prefix"`

	// KeyHash is the SHA256 hash of the full key.
	KeyHash string `db:"key_hash" json:"key_hash"`

	// Hint is the last few characters of the key for identification.
	Hint string `db:"hint" json:"hint"`

	// Scopes limits the key to specific permissions (nil = all permissions).
	Scopes []string `db:"scopes" json:"scopes,omitempty"`

	// CreatedAt is when the key was created.
	CreatedAt time.Time `db:"created_at" json:"created_at"`

	// ExpiresAt is when the key expires (nil = never).
	ExpiresAt *time.Time `db:"expires_at" json:"expires_at,omitempty"`

	// LastUsedAt is when the key was last used.
	LastUsedAt *time.Time `db:"last_used_at" json:"last_used_at,omitempty"`

	// RevokedAt is when the key was revoked (nil = active).
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
}

// IsRevoked returns true if the key has been revoked.
func (k *APIKey) IsRevoked() bool {
	return k.RevokedAt != nil
}

// IsExpired returns true if the key has expired.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsValid returns true if the key is neither revoked nor expired.
func (k *APIKey) IsValid() bool {
	return !k.IsRevoked() && !k.IsExpired()
}

// HasScope checks if the key has access to a permission.
// Empty scopes means all permissions.
func (k *APIKey) HasScope(permission string) bool {
	if len(k.Scopes) == 0 {
		return true
	}
	for _, s := range k.Scopes {
		if matchPermission(s, permission) {
			return true
		}
	}
	return false
}
