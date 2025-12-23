// Package middleware provides HTTP middleware for goauth authentication.
package middleware

import (
	"context"
	"net/http"
	"strings"
)

// contextKey is a type for context keys to avoid collisions.
type contextKey string

const (
	// ClaimsKey is the context key for storing claims.
	ClaimsKey contextKey = "goauth_claims"
	// UserIDKey is the context key for storing user ID.
	UserIDKey contextKey = "goauth_user_id"
	// PermissionsKey is the context key for storing permissions.
	PermissionsKey contextKey = "goauth_permissions"
	// APIKeyKey is the context key for storing API key info.
	APIKeyKey contextKey = "goauth_api_key"
)

// TokenExtractor extracts a token from an HTTP request.
type TokenExtractor func(r *http.Request) string

// ErrorHandler handles authentication errors.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Config holds middleware configuration.
type Config struct {
	// TokenExtractor extracts the token from the request.
	// Defaults to extracting from Authorization header.
	TokenExtractor TokenExtractor

	// ErrorHandler handles authentication errors.
	// Defaults to returning 401 Unauthorized.
	ErrorHandler ErrorHandler

	// SkipPaths are paths that skip authentication.
	SkipPaths []string

	// Optional: custom context key for claims
	ClaimsContextKey contextKey
}

// DefaultConfig returns a default middleware configuration.
func DefaultConfig() *Config {
	return &Config{
		TokenExtractor:   ExtractFromHeader("Authorization", "Bearer"),
		ErrorHandler:     DefaultErrorHandler,
		ClaimsContextKey: ClaimsKey,
	}
}

// ExtractFromHeader creates a TokenExtractor that extracts from a header.
func ExtractFromHeader(header, scheme string) TokenExtractor {
	return func(r *http.Request) string {
		auth := r.Header.Get(header)
		if auth == "" {
			return ""
		}

		if scheme != "" {
			prefix := scheme + " "
			if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
				return auth[len(prefix):]
			}
			return ""
		}

		return auth
	}
}

// ExtractFromQuery creates a TokenExtractor that extracts from a query parameter.
func ExtractFromQuery(param string) TokenExtractor {
	return func(r *http.Request) string {
		return r.URL.Query().Get(param)
	}
}

// ExtractFromCookie creates a TokenExtractor that extracts from a cookie.
func ExtractFromCookie(name string) TokenExtractor {
	return func(r *http.Request) string {
		cookie, err := r.Cookie(name)
		if err != nil {
			return ""
		}
		return cookie.Value
	}
}

// ChainExtractors chains multiple extractors, returning the first non-empty result.
func ChainExtractors(extractors ...TokenExtractor) TokenExtractor {
	return func(r *http.Request) string {
		for _, extractor := range extractors {
			if token := extractor(r); token != "" {
				return token
			}
		}
		return ""
	}
}

// DefaultErrorHandler is the default error handler.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	code := ErrorToHTTPStatus(err)
	http.Error(w, http.StatusText(code), code)
}

// ErrorToHTTPStatus converts an error to an HTTP status code.
func ErrorToHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	errStr := err.Error()

	// Map common error messages to status codes
	switch {
	case strings.Contains(errStr, "token") && strings.Contains(errStr, "expired"):
		return http.StatusUnauthorized
	case strings.Contains(errStr, "token") && strings.Contains(errStr, "invalid"):
		return http.StatusUnauthorized
	case strings.Contains(errStr, "token") && strings.Contains(errStr, "blacklisted"):
		return http.StatusUnauthorized
	case strings.Contains(errStr, "token") && strings.Contains(errStr, "missing"):
		return http.StatusUnauthorized
	case strings.Contains(errStr, "permission"):
		return http.StatusForbidden
	case strings.Contains(errStr, "revoked"):
		return http.StatusUnauthorized
	case strings.Contains(errStr, "not found"):
		return http.StatusNotFound
	default:
		return http.StatusUnauthorized
	}
}

// ShouldSkip checks if the request path should skip authentication.
func ShouldSkip(r *http.Request, skipPaths []string) bool {
	path := r.URL.Path
	for _, skip := range skipPaths {
		if matchPath(skip, path) {
			return true
		}
	}
	return false
}

// matchPath checks if a path matches a pattern.
// Supports * as a wildcard for path segments.
func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}

	// Handle wildcard patterns like /api/*
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-2]
		return strings.HasPrefix(path, prefix)
	}

	// Handle wildcard patterns like /api/*/users
	if strings.Contains(pattern, "*") {
		patternParts := strings.Split(pattern, "/")
		pathParts := strings.Split(path, "/")

		if len(patternParts) != len(pathParts) {
			return false
		}

		for i, part := range patternParts {
			if part != "*" && part != pathParts[i] {
				return false
			}
		}
		return true
	}

	return false
}

// SetClaims stores claims in the request context.
func SetClaims(ctx context.Context, claims interface{}) context.Context {
	return context.WithValue(ctx, ClaimsKey, claims)
}

// GetClaims retrieves claims from the context.
func GetClaims(ctx context.Context) interface{} {
	return ctx.Value(ClaimsKey)
}

// SetUserID stores user ID in the request context.
func SetUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// GetUserID retrieves user ID from the context.
func GetUserID(ctx context.Context) string {
	if v := ctx.Value(UserIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// SetPermissions stores permissions in the request context.
func SetPermissions(ctx context.Context, permissions []string) context.Context {
	return context.WithValue(ctx, PermissionsKey, permissions)
}

// GetPermissions retrieves permissions from the context.
func GetPermissions(ctx context.Context) []string {
	if v := ctx.Value(PermissionsKey); v != nil {
		if p, ok := v.([]string); ok {
			return p
		}
	}
	return nil
}

// APIKeyInfo holds API key information stored in context.
type APIKeyInfo struct {
	ID     string
	UserID string
	Scopes []string
}

// SetAPIKeyInfo stores API key info in the request context.
func SetAPIKeyInfo(ctx context.Context, info *APIKeyInfo) context.Context {
	return context.WithValue(ctx, APIKeyKey, info)
}

// GetAPIKeyInfo retrieves API key info from the context.
func GetAPIKeyInfo(ctx context.Context) *APIKeyInfo {
	if v := ctx.Value(APIKeyKey); v != nil {
		if info, ok := v.(*APIKeyInfo); ok {
			return info
		}
	}
	return nil
}
