package goauth

import (
	"time"
)

// StandardClaims contains the standard JWT claims used by goauth.
// Custom claims must embed this struct.
type StandardClaims struct {
	// UserID is the subject (sub) claim - typically the user's unique identifier.
	UserID string `json:"sub"`

	// JTI is the JWT ID - a unique identifier for the token.
	JTI string `json:"jti"`

	// IssuedAt is the time the token was issued (Unix timestamp).
	IssuedAt int64 `json:"iat"`

	// ExpiresAt is the expiration time (Unix timestamp).
	ExpiresAt int64 `json:"exp"`

	// PermissionVersion tracks the version of user permissions.
	// When permissions change, this version is bumped, invalidating old tokens.
	PermissionVersion int `json:"pv,omitempty"`
}

// GetStandardClaims returns a pointer to the StandardClaims.
// This satisfies the Claims interface.
func (c *StandardClaims) GetStandardClaims() *StandardClaims {
	return c
}

// GetUserID returns the user ID from the claims.
func (c *StandardClaims) GetUserID() string {
	return c.UserID
}

// GetJTI returns the JWT ID.
func (c *StandardClaims) GetJTI() string {
	return c.JTI
}

// GetIssuedAt returns the issued at time.
func (c *StandardClaims) GetIssuedAt() time.Time {
	return time.Unix(c.IssuedAt, 0)
}

// GetExpiresAt returns the expiration time.
func (c *StandardClaims) GetExpiresAt() time.Time {
	return time.Unix(c.ExpiresAt, 0)
}

// IsExpired returns true if the token has expired.
func (c *StandardClaims) IsExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// IsNotYetValid returns true if the token's issued at time is in the future.
func (c *StandardClaims) IsNotYetValid() bool {
	return time.Now().Unix() < c.IssuedAt
}

// TimeUntilExpiry returns the duration until the token expires.
// Returns a negative duration if already expired.
func (c *StandardClaims) TimeUntilExpiry() time.Duration {
	return time.Until(c.GetExpiresAt())
}

// Claims is the interface that custom claim types must implement.
// Any struct embedding StandardClaims will satisfy this interface.
type Claims interface {
	GetStandardClaims() *StandardClaims
}

// ClaimsFromContext extracts claims of type T from a context.
// This is a convenience function for use in handlers.
// Returns nil if claims are not present or of wrong type.
func ClaimsFromContext[T Claims](ctx interface{ Value(any) any }, key any) T {
	val := ctx.Value(key)
	if val == nil {
		var zero T
		return zero
	}
	claims, ok := val.(T)
	if !ok {
		var zero T
		return zero
	}
	return claims
}
