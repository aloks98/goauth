package app

import (
	"context"

	"github.com/aloks98/goauth"
	"github.com/aloks98/goauth/middleware"
	"github.com/aloks98/goauth/token"
)

// AuthAdapter implements middleware interfaces for goauth.Auth.
type AuthAdapter struct {
	auth *goauth.Auth[*Claims]
}

// NewAuthAdapter creates a new adapter for the given auth instance.
func NewAuthAdapter(auth *goauth.Auth[*Claims]) *AuthAdapter {
	return &AuthAdapter{auth: auth}
}

// ValidateAccessToken implements middleware.TokenValidator.
func (a *AuthAdapter) ValidateAccessToken(ctx context.Context, tokenString string) (interface{}, error) {
	return a.auth.ValidateAccessToken(ctx, tokenString)
}

// ExtractUserID implements middleware.ClaimsExtractor.
func (a *AuthAdapter) ExtractUserID(claims interface{}) string {
	if c, ok := claims.(*token.Claims); ok {
		return c.UserID
	}
	return ""
}

// ExtractPermissions implements middleware.ClaimsExtractor.
// Permissions are not stored in JWT claims - they're fetched from the store.
func (a *AuthAdapter) ExtractPermissions(claims interface{}) []string {
	// Permissions are managed through RBAC store, not in JWT claims
	return nil
}

// HasPermission implements middleware.PermissionChecker.
func (a *AuthAdapter) HasPermission(ctx context.Context, userID, permission string) (bool, error) {
	return a.auth.HasPermission(ctx, userID, permission)
}

// HasAllPermissions implements middleware.PermissionChecker.
func (a *AuthAdapter) HasAllPermissions(ctx context.Context, userID string, permissions []string) (bool, error) {
	return a.auth.HasAllPermissions(ctx, userID, permissions)
}

// HasAnyPermission implements middleware.PermissionChecker.
func (a *AuthAdapter) HasAnyPermission(ctx context.Context, userID string, permissions []string) (bool, error) {
	return a.auth.HasAnyPermission(ctx, userID, permissions)
}

// ValidateAPIKey implements middleware.APIKeyValidator.
func (a *AuthAdapter) ValidateAPIKey(ctx context.Context, rawKey string) (*middleware.APIKeyInfo, error) {
	result, err := a.auth.ValidateAPIKey(ctx, rawKey)
	if err != nil {
		return nil, err
	}
	return &middleware.APIKeyInfo{
		ID:     result.Key.ID,
		UserID: result.UserID,
		Scopes: result.Key.Scopes,
	}, nil
}

// Ensure AuthAdapter implements all required interfaces.
var (
	_ middleware.TokenValidator    = (*AuthAdapter)(nil)
	_ middleware.ClaimsExtractor   = (*AuthAdapter)(nil)
	_ middleware.PermissionChecker = (*AuthAdapter)(nil)
	_ middleware.APIKeyValidator   = (*AuthAdapter)(nil)
)
