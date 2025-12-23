// Package chi provides Chi middleware for goauth authentication.
// Chi uses standard net/http middleware, so this package provides
// aliases and helpers for convenience.
package chi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aloks98/goauth/middleware"
)

// Config is an alias for middleware.Config.
type Config = middleware.Config

// TokenValidator is an alias for middleware.TokenValidator.
type TokenValidator = middleware.TokenValidator

// PermissionChecker is an alias for middleware.PermissionChecker.
type PermissionChecker = middleware.PermissionChecker

// APIKeyValidator is an alias for middleware.APIKeyValidator.
type APIKeyValidator = middleware.APIKeyValidator

// ClaimsExtractor is an alias for middleware.ClaimsExtractor.
type ClaimsExtractor = middleware.ClaimsExtractor

// APIKeyInfo is an alias for middleware.APIKeyInfo.
type APIKeyInfo = middleware.APIKeyInfo

// DefaultConfig returns a default middleware configuration.
func DefaultConfig() *Config {
	return middleware.DefaultConfig()
}

// Authenticate creates a Chi middleware that validates JWT tokens.
func Authenticate(validator TokenValidator, extractor ClaimsExtractor, cfg *Config) func(http.Handler) http.Handler {
	return middleware.Authenticate(validator, extractor, cfg)
}

// RequirePermission creates a Chi middleware that checks for a specific permission.
func RequirePermission(checker PermissionChecker, permission string, cfg *Config) func(http.Handler) http.Handler {
	return middleware.RequirePermission(checker, permission, cfg)
}

// RequireAllPermissions creates a Chi middleware that checks for all specified permissions.
func RequireAllPermissions(checker PermissionChecker, permissions []string, cfg *Config) func(http.Handler) http.Handler {
	return middleware.RequireAllPermissions(checker, permissions, cfg)
}

// RequireAnyPermission creates a Chi middleware that checks for any of the specified permissions.
func RequireAnyPermission(checker PermissionChecker, permissions []string, cfg *Config) func(http.Handler) http.Handler {
	return middleware.RequireAnyPermission(checker, permissions, cfg)
}

// AuthenticateAPIKey creates a Chi middleware that validates API keys.
func AuthenticateAPIKey(validator APIKeyValidator, cfg *Config) func(http.Handler) http.Handler {
	return middleware.AuthenticateAPIKey(validator, cfg)
}

// RequireScope creates a Chi middleware that checks for a specific API key scope.
func RequireScope(scope string, cfg *Config) func(http.Handler) http.Handler {
	return middleware.RequireScope(scope, cfg)
}

// OptionalAuthenticate creates a middleware that validates JWT tokens if present.
func OptionalAuthenticate(validator TokenValidator, extractor ClaimsExtractor, cfg *Config) func(http.Handler) http.Handler {
	return middleware.OptionalAuthenticate(validator, extractor, cfg)
}

// Claims retrieves claims from request context.
func Claims[T any](r *http.Request) (T, bool) {
	var zero T
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		return zero, false
	}
	typed, ok := claims.(T)
	return typed, ok
}

// UserID retrieves user ID from request context.
func UserID(r *http.Request) string {
	return middleware.GetUserID(r.Context())
}

// Permissions retrieves permissions from request context.
func Permissions(r *http.Request) []string {
	return middleware.GetPermissions(r.Context())
}

// GetAPIKeyInfo retrieves API key info from request context.
func GetAPIKeyInfo(r *http.Request) *APIKeyInfo {
	return middleware.GetAPIKeyInfo(r.Context())
}

// RouteContext returns Chi's route context from the request.
func RouteContext(r *http.Request) *chi.Context {
	return chi.RouteContext(r.Context())
}

// URLParam returns a URL parameter from Chi's route context.
func URLParam(r *http.Request, key string) string {
	return chi.URLParam(r, key)
}
