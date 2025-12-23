package middleware

import (
	"context"
	"errors"
	"net/http"
)

// TokenValidator validates a JWT token and returns claims.
type TokenValidator interface {
	ValidateAccessToken(ctx context.Context, tokenString string) (claims interface{}, err error)
}

// PermissionChecker checks if a user has required permissions.
type PermissionChecker interface {
	HasPermission(ctx context.Context, userID string, permission string) (bool, error)
	HasAllPermissions(ctx context.Context, userID string, permissions []string) (bool, error)
	HasAnyPermission(ctx context.Context, userID string, permissions []string) (bool, error)
}

// APIKeyValidator validates an API key.
type APIKeyValidator interface {
	ValidateAPIKey(ctx context.Context, rawKey string) (keyInfo *APIKeyInfo, err error)
}

// ClaimsExtractor extracts user ID and other info from claims.
type ClaimsExtractor interface {
	ExtractUserID(claims interface{}) string
	ExtractPermissions(claims interface{}) []string
}

// Common errors
var (
	ErrMissingToken      = errors.New("missing authentication token")
	ErrInvalidToken      = errors.New("invalid authentication token")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrRBACNotConfigured = errors.New("RBAC is not configured")
)

// Authenticate creates a middleware that validates JWT tokens.
func Authenticate(validator TokenValidator, extractor ClaimsExtractor, cfg *Config) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be skipped
			if ShouldSkip(r, cfg.SkipPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract token
			token := cfg.TokenExtractor(r)
			if token == "" {
				cfg.ErrorHandler(w, r, ErrMissingToken)
				return
			}

			// Validate token
			claims, err := validator.ValidateAccessToken(r.Context(), token)
			if err != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}

			// Store claims in context
			ctx := SetClaims(r.Context(), claims)

			// Extract and store user ID
			if extractor != nil {
				userID := extractor.ExtractUserID(claims)
				ctx = SetUserID(ctx, userID)

				// Extract and store permissions if available
				permissions := extractor.ExtractPermissions(claims)
				if len(permissions) > 0 {
					ctx = SetPermissions(ctx, permissions)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission creates a middleware that checks for a specific permission.
func RequirePermission(checker PermissionChecker, permission string, cfg *Config) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				cfg.ErrorHandler(w, r, ErrRBACNotConfigured)
				return
			}

			userID := GetUserID(r.Context())
			if userID == "" {
				cfg.ErrorHandler(w, r, ErrMissingToken)
				return
			}

			hasPermission, err := checker.HasPermission(r.Context(), userID, permission)
			if err != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}

			if !hasPermission {
				cfg.ErrorHandler(w, r, ErrPermissionDenied)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllPermissions creates a middleware that checks for all specified permissions.
func RequireAllPermissions(checker PermissionChecker, permissions []string, cfg *Config) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				cfg.ErrorHandler(w, r, ErrRBACNotConfigured)
				return
			}

			userID := GetUserID(r.Context())
			if userID == "" {
				cfg.ErrorHandler(w, r, ErrMissingToken)
				return
			}

			hasAll, err := checker.HasAllPermissions(r.Context(), userID, permissions)
			if err != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}

			if !hasAll {
				cfg.ErrorHandler(w, r, ErrPermissionDenied)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission creates a middleware that checks for any of the specified permissions.
func RequireAnyPermission(checker PermissionChecker, permissions []string, cfg *Config) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				cfg.ErrorHandler(w, r, ErrRBACNotConfigured)
				return
			}

			userID := GetUserID(r.Context())
			if userID == "" {
				cfg.ErrorHandler(w, r, ErrMissingToken)
				return
			}

			hasAny, err := checker.HasAnyPermission(r.Context(), userID, permissions)
			if err != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}

			if !hasAny {
				cfg.ErrorHandler(w, r, ErrPermissionDenied)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuthenticateAPIKey creates a middleware that validates API keys.
func AuthenticateAPIKey(validator APIKeyValidator, cfg *Config) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Default to X-API-Key header for API keys
	extractor := cfg.TokenExtractor
	if extractor == nil {
		extractor = ExtractFromHeader("X-API-Key", "")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be skipped
			if ShouldSkip(r, cfg.SkipPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract API key
			apiKey := extractor(r)
			if apiKey == "" {
				cfg.ErrorHandler(w, r, ErrMissingToken)
				return
			}

			// Validate API key
			keyInfo, err := validator.ValidateAPIKey(r.Context(), apiKey)
			if err != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}

			// Store key info in context
			ctx := SetAPIKeyInfo(r.Context(), keyInfo)
			ctx = SetUserID(ctx, keyInfo.UserID)
			if len(keyInfo.Scopes) > 0 {
				ctx = SetPermissions(ctx, keyInfo.Scopes)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope creates a middleware that checks for a specific API key scope.
func RequireScope(scope string, cfg *Config) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keyInfo := GetAPIKeyInfo(r.Context())
			if keyInfo == nil {
				cfg.ErrorHandler(w, r, ErrMissingToken)
				return
			}

			// Empty scopes means full access
			if len(keyInfo.Scopes) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Check if scope is present
			for _, s := range keyInfo.Scopes {
				if matchScope(s, scope) {
					next.ServeHTTP(w, r)
					return
				}
			}

			cfg.ErrorHandler(w, r, ErrPermissionDenied)
		})
	}
}

// matchScope checks if a scope matches a required scope.
// Supports wildcard matching.
func matchScope(have, want string) bool {
	if have == "*" || have == want {
		return true
	}

	// Check for resource:* patterns
	haveParts := splitScope(have)
	wantParts := splitScope(want)

	if len(haveParts) == 2 && len(wantParts) == 2 {
		if haveParts[0] == "*" && haveParts[1] == wantParts[1] {
			return true
		}
		if haveParts[1] == "*" && haveParts[0] == wantParts[0] {
			return true
		}
	}

	return false
}

// splitScope splits a scope into resource and action.
func splitScope(scope string) []string {
	for i := 0; i < len(scope); i++ {
		if scope[i] == ':' {
			return []string{scope[:i], scope[i+1:]}
		}
	}
	return []string{scope}
}

// OptionalAuthenticate creates a middleware that validates JWT tokens if present,
// but allows unauthenticated requests to proceed.
func OptionalAuthenticate(validator TokenValidator, extractor ClaimsExtractor, cfg *Config) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token
			token := cfg.TokenExtractor(r)
			if token == "" {
				// No token, continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			// Validate token
			claims, err := validator.ValidateAccessToken(r.Context(), token)
			if err != nil {
				// Invalid token, continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			// Store claims in context
			ctx := SetClaims(r.Context(), claims)

			// Extract and store user ID
			if extractor != nil {
				userID := extractor.ExtractUserID(claims)
				ctx = SetUserID(ctx, userID)

				permissions := extractor.ExtractPermissions(claims)
				if len(permissions) > 0 {
					ctx = SetPermissions(ctx, permissions)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
