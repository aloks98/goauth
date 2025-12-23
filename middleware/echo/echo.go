// Package echo provides Echo middleware for goauth authentication.
package echo

import (
	"context"

	"github.com/labstack/echo/v4"

	"github.com/aloks98/goauth/middleware"
)

// Config holds Echo-specific middleware configuration.
type Config struct {
	// TokenExtractor extracts the token from the Echo context.
	// Defaults to extracting from Authorization header.
	TokenExtractor TokenExtractor

	// ErrorHandler handles authentication errors.
	// Defaults to returning 401 Unauthorized.
	ErrorHandler ErrorHandler

	// SkipPaths are paths that skip authentication.
	SkipPaths []string

	// ContextKey is the key used to store claims in Echo's context.
	ContextKey string
}

// TokenExtractor extracts a token from an Echo context.
type TokenExtractor func(c echo.Context) string

// ErrorHandler handles authentication errors in Echo.
type ErrorHandler func(c echo.Context, err error) error

// TokenValidator validates a JWT token and returns claims.
type TokenValidator interface {
	ValidateAccessToken(ctx context.Context, tokenString string) (claims interface{}, err error)
}

// PermissionChecker checks if a user has required permissions.
type PermissionChecker interface {
	HasPermission(ctx context.Context, userID string, permission string) (bool, error)
}

// APIKeyValidator validates an API key.
type APIKeyValidator interface {
	ValidateAPIKey(ctx context.Context, rawKey string) (keyInfo *middleware.APIKeyInfo, err error)
}

// ClaimsExtractor extracts user ID and other info from claims.
type ClaimsExtractor interface {
	ExtractUserID(claims interface{}) string
	ExtractPermissions(claims interface{}) []string
}

// DefaultConfig returns a default Echo middleware configuration.
func DefaultConfig() *Config {
	return &Config{
		TokenExtractor: ExtractFromHeader("Authorization", "Bearer"),
		ErrorHandler:   DefaultErrorHandler,
		ContextKey:     "claims",
	}
}

// ExtractFromHeader creates a token extractor that extracts from a header.
func ExtractFromHeader(header, scheme string) TokenExtractor {
	return func(c echo.Context) string {
		auth := c.Request().Header.Get(header)
		if auth == "" {
			return ""
		}

		if scheme != "" {
			prefix := scheme + " "
			if len(auth) > len(prefix) && equalFold(auth[:len(prefix)], prefix) {
				return auth[len(prefix):]
			}
			return ""
		}

		return auth
	}
}

// ExtractFromQuery creates a token extractor that extracts from a query parameter.
func ExtractFromQuery(param string) TokenExtractor {
	return func(c echo.Context) string {
		return c.QueryParam(param)
	}
}

// ExtractFromCookie creates a token extractor that extracts from a cookie.
func ExtractFromCookie(name string) TokenExtractor {
	return func(c echo.Context) string {
		cookie, err := c.Cookie(name)
		if err != nil {
			return ""
		}
		return cookie.Value
	}
}

// DefaultErrorHandler is the default error handler for Echo.
func DefaultErrorHandler(c echo.Context, err error) error {
	code := middleware.ErrorToHTTPStatus(err)
	return c.String(code, err.Error())
}

// Authenticate creates an Echo middleware that validates JWT tokens.
func Authenticate(validator TokenValidator, extractor ClaimsExtractor, cfg *Config) echo.MiddlewareFunc {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check if path should be skipped
			if shouldSkip(c, cfg.SkipPaths) {
				return next(c)
			}

			// Extract token
			token := cfg.TokenExtractor(c)
			if token == "" {
				return cfg.ErrorHandler(c, middleware.ErrMissingToken)
			}

			// Validate token
			claims, err := validator.ValidateAccessToken(c.Request().Context(), token)
			if err != nil {
				return cfg.ErrorHandler(c, err)
			}

			// Store claims in context
			c.Set(cfg.ContextKey, claims)

			// Extract and store user ID
			if extractor != nil {
				userID := extractor.ExtractUserID(claims)
				c.Set("user_id", userID)

				permissions := extractor.ExtractPermissions(claims)
				if len(permissions) > 0 {
					c.Set("permissions", permissions)
				}
			}

			return next(c)
		}
	}
}

// RequirePermission creates an Echo middleware that checks for a specific permission.
func RequirePermission(checker PermissionChecker, permission string, cfg *Config) echo.MiddlewareFunc {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if checker == nil {
				return cfg.ErrorHandler(c, middleware.ErrRBACNotConfigured)
			}

			userID, ok := c.Get("user_id").(string)
			if !ok || userID == "" {
				return cfg.ErrorHandler(c, middleware.ErrMissingToken)
			}

			hasPermission, err := checker.HasPermission(c.Request().Context(), userID, permission)
			if err != nil {
				return cfg.ErrorHandler(c, err)
			}

			if !hasPermission {
				return cfg.ErrorHandler(c, middleware.ErrPermissionDenied)
			}

			return next(c)
		}
	}
}

// AuthenticateAPIKey creates an Echo middleware that validates API keys.
func AuthenticateAPIKey(validator APIKeyValidator, cfg *Config) echo.MiddlewareFunc {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	extractor := cfg.TokenExtractor
	if extractor == nil {
		extractor = ExtractFromHeader("X-API-Key", "")
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check if path should be skipped
			if shouldSkip(c, cfg.SkipPaths) {
				return next(c)
			}

			// Extract API key
			apiKey := extractor(c)
			if apiKey == "" {
				return cfg.ErrorHandler(c, middleware.ErrMissingToken)
			}

			// Validate API key
			keyInfo, err := validator.ValidateAPIKey(c.Request().Context(), apiKey)
			if err != nil {
				return cfg.ErrorHandler(c, err)
			}

			// Store key info in context
			c.Set("api_key", keyInfo)
			c.Set("user_id", keyInfo.UserID)
			if len(keyInfo.Scopes) > 0 {
				c.Set("scopes", keyInfo.Scopes)
			}

			return next(c)
		}
	}
}

// Claims retrieves claims from Echo context.
func Claims[T any](c echo.Context, key string) (T, bool) {
	var zero T
	claims := c.Get(key)
	if claims == nil {
		return zero, false
	}
	typed, ok := claims.(T)
	return typed, ok
}

// UserID retrieves user ID from Echo context.
func UserID(c echo.Context) string {
	if v := c.Get("user_id"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// shouldSkip checks if the Echo request path should skip authentication.
func shouldSkip(c echo.Context, skipPaths []string) bool {
	path := c.Request().URL.Path
	for _, skip := range skipPaths {
		if matchPath(skip, path) {
			return true
		}
	}
	return false
}

// matchPath checks if a path matches a pattern.
func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if len(pattern) > 2 && pattern[len(pattern)-2:] == "/*" {
		prefix := pattern[:len(pattern)-2]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return false
}

// equalFold is a case-insensitive string comparison.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
