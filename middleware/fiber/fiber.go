// Package fiber provides Fiber middleware for goauth authentication.
package fiber

import (
	"context"

	"github.com/gofiber/fiber/v2"

	"github.com/aloks98/goauth/middleware"
)

// Config holds Fiber-specific middleware configuration.
type Config struct {
	// TokenExtractor extracts the token from the Fiber context.
	// Defaults to extracting from Authorization header.
	TokenExtractor TokenExtractor

	// ErrorHandler handles authentication errors.
	// Defaults to returning 401 Unauthorized.
	ErrorHandler ErrorHandler

	// SkipPaths are paths that skip authentication.
	SkipPaths []string

	// ContextKey is the key used to store claims in Fiber's Locals.
	ContextKey string
}

// TokenExtractor extracts a token from a Fiber context.
type TokenExtractor func(c *fiber.Ctx) string

// ErrorHandler handles authentication errors in Fiber.
type ErrorHandler func(c *fiber.Ctx, err error) error

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

// DefaultConfig returns a default Fiber middleware configuration.
func DefaultConfig() *Config {
	return &Config{
		TokenExtractor: ExtractFromHeader("Authorization", "Bearer"),
		ErrorHandler:   DefaultErrorHandler,
		ContextKey:     "claims",
	}
}

// ExtractFromHeader creates a token extractor that extracts from a header.
func ExtractFromHeader(header, scheme string) TokenExtractor {
	return func(c *fiber.Ctx) string {
		auth := c.Get(header)
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
	return func(c *fiber.Ctx) string {
		return c.Query(param)
	}
}

// ExtractFromCookie creates a token extractor that extracts from a cookie.
func ExtractFromCookie(name string) TokenExtractor {
	return func(c *fiber.Ctx) string {
		return c.Cookies(name)
	}
}

// DefaultErrorHandler is the default error handler for Fiber.
func DefaultErrorHandler(c *fiber.Ctx, err error) error {
	code := middleware.ErrorToHTTPStatus(err)
	return c.Status(code).SendString(err.Error())
}

// Authenticate creates a Fiber middleware that validates JWT tokens.
func Authenticate(validator TokenValidator, extractor ClaimsExtractor, cfg *Config) fiber.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(c *fiber.Ctx) error {
		// Check if path should be skipped
		if shouldSkip(c, cfg.SkipPaths) {
			return c.Next()
		}

		// Extract token
		token := cfg.TokenExtractor(c)
		if token == "" {
			return cfg.ErrorHandler(c, middleware.ErrMissingToken)
		}

		// Validate token
		claims, err := validator.ValidateAccessToken(c.UserContext(), token)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		// Store claims in context
		c.Locals(cfg.ContextKey, claims)

		// Extract and store user ID
		if extractor != nil {
			userID := extractor.ExtractUserID(claims)
			c.Locals("user_id", userID)

			permissions := extractor.ExtractPermissions(claims)
			if len(permissions) > 0 {
				c.Locals("permissions", permissions)
			}
		}

		return c.Next()
	}
}

// RequirePermission creates a Fiber middleware that checks for a specific permission.
func RequirePermission(checker PermissionChecker, permission string, cfg *Config) fiber.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(c *fiber.Ctx) error {
		if checker == nil {
			return cfg.ErrorHandler(c, middleware.ErrRBACNotConfigured)
		}

		userID, ok := c.Locals("user_id").(string)
		if !ok || userID == "" {
			return cfg.ErrorHandler(c, middleware.ErrMissingToken)
		}

		hasPermission, err := checker.HasPermission(c.UserContext(), userID, permission)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		if !hasPermission {
			return cfg.ErrorHandler(c, middleware.ErrPermissionDenied)
		}

		return c.Next()
	}
}

// AuthenticateAPIKey creates a Fiber middleware that validates API keys.
func AuthenticateAPIKey(validator APIKeyValidator, cfg *Config) fiber.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	extractor := cfg.TokenExtractor
	if extractor == nil {
		extractor = ExtractFromHeader("X-API-Key", "")
	}

	return func(c *fiber.Ctx) error {
		// Check if path should be skipped
		if shouldSkip(c, cfg.SkipPaths) {
			return c.Next()
		}

		// Extract API key
		apiKey := extractor(c)
		if apiKey == "" {
			return cfg.ErrorHandler(c, middleware.ErrMissingToken)
		}

		// Validate API key
		keyInfo, err := validator.ValidateAPIKey(c.UserContext(), apiKey)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		// Store key info in context
		c.Locals("api_key", keyInfo)
		c.Locals("user_id", keyInfo.UserID)
		if len(keyInfo.Scopes) > 0 {
			c.Locals("scopes", keyInfo.Scopes)
		}

		return c.Next()
	}
}

// Claims retrieves claims from Fiber context.
func Claims[T any](c *fiber.Ctx, key string) (T, bool) {
	var zero T
	claims := c.Locals(key)
	if claims == nil {
		return zero, false
	}
	typed, ok := claims.(T)
	return typed, ok
}

// UserID retrieves user ID from Fiber context.
func UserID(c *fiber.Ctx) string {
	if v := c.Locals("user_id"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// shouldSkip checks if the Fiber request path should skip authentication.
func shouldSkip(c *fiber.Ctx, skipPaths []string) bool {
	path := c.Path()
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
