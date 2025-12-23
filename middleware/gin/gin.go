// Package gin provides Gin middleware for goauth authentication.
package gin

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/aloks98/goauth/middleware"
)

// Config holds Gin-specific middleware configuration.
type Config struct {
	// TokenExtractor extracts the token from the Gin context.
	// Defaults to extracting from Authorization header.
	TokenExtractor TokenExtractor

	// ErrorHandler handles authentication errors.
	// Defaults to returning 401 Unauthorized.
	ErrorHandler ErrorHandler

	// SkipPaths are paths that skip authentication.
	SkipPaths []string

	// ContextKey is the key used to store claims in Gin's context.
	ContextKey string
}

// TokenExtractor extracts a token from a Gin context.
type TokenExtractor func(c *gin.Context) string

// ErrorHandler handles authentication errors in Gin.
type ErrorHandler func(c *gin.Context, err error)

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

// DefaultConfig returns a default Gin middleware configuration.
func DefaultConfig() *Config {
	return &Config{
		TokenExtractor: ExtractFromHeader("Authorization", "Bearer"),
		ErrorHandler:   DefaultErrorHandler,
		ContextKey:     "claims",
	}
}

// ExtractFromHeader creates a token extractor that extracts from a header.
func ExtractFromHeader(header, scheme string) TokenExtractor {
	return func(c *gin.Context) string {
		auth := c.GetHeader(header)
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
	return func(c *gin.Context) string {
		return c.Query(param)
	}
}

// ExtractFromCookie creates a token extractor that extracts from a cookie.
func ExtractFromCookie(name string) TokenExtractor {
	return func(c *gin.Context) string {
		cookie, err := c.Cookie(name)
		if err != nil {
			return ""
		}
		return cookie
	}
}

// DefaultErrorHandler is the default error handler for Gin.
func DefaultErrorHandler(c *gin.Context, err error) {
	code := middleware.ErrorToHTTPStatus(err)
	c.AbortWithStatusJSON(code, gin.H{"error": err.Error()})
}

// Authenticate creates a Gin middleware that validates JWT tokens.
func Authenticate(validator TokenValidator, extractor ClaimsExtractor, cfg *Config) gin.HandlerFunc {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(c *gin.Context) {
		// Check if path should be skipped
		if shouldSkip(c, cfg.SkipPaths) {
			c.Next()
			return
		}

		// Extract token
		token := cfg.TokenExtractor(c)
		if token == "" {
			cfg.ErrorHandler(c, middleware.ErrMissingToken)
			return
		}

		// Validate token
		claims, err := validator.ValidateAccessToken(c.Request.Context(), token)
		if err != nil {
			cfg.ErrorHandler(c, err)
			return
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

		c.Next()
	}
}

// RequirePermission creates a Gin middleware that checks for a specific permission.
func RequirePermission(checker PermissionChecker, permission string, cfg *Config) gin.HandlerFunc {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return func(c *gin.Context) {
		if checker == nil {
			cfg.ErrorHandler(c, middleware.ErrRBACNotConfigured)
			return
		}

		userID, exists := c.Get("user_id")
		if !exists {
			cfg.ErrorHandler(c, middleware.ErrMissingToken)
			return
		}

		userIDStr, ok := userID.(string)
		if !ok || userIDStr == "" {
			cfg.ErrorHandler(c, middleware.ErrMissingToken)
			return
		}

		hasPermission, err := checker.HasPermission(c.Request.Context(), userIDStr, permission)
		if err != nil {
			cfg.ErrorHandler(c, err)
			return
		}

		if !hasPermission {
			cfg.ErrorHandler(c, middleware.ErrPermissionDenied)
			return
		}

		c.Next()
	}
}

// AuthenticateAPIKey creates a Gin middleware that validates API keys.
func AuthenticateAPIKey(validator APIKeyValidator, cfg *Config) gin.HandlerFunc {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	extractor := cfg.TokenExtractor
	if extractor == nil {
		extractor = ExtractFromHeader("X-API-Key", "")
	}

	return func(c *gin.Context) {
		// Check if path should be skipped
		if shouldSkip(c, cfg.SkipPaths) {
			c.Next()
			return
		}

		// Extract API key
		apiKey := extractor(c)
		if apiKey == "" {
			cfg.ErrorHandler(c, middleware.ErrMissingToken)
			return
		}

		// Validate API key
		keyInfo, err := validator.ValidateAPIKey(c.Request.Context(), apiKey)
		if err != nil {
			cfg.ErrorHandler(c, err)
			return
		}

		// Store key info in context
		c.Set("api_key", keyInfo)
		c.Set("user_id", keyInfo.UserID)
		if len(keyInfo.Scopes) > 0 {
			c.Set("scopes", keyInfo.Scopes)
		}

		c.Next()
	}
}

// Claims retrieves claims from Gin context.
func Claims[T any](c *gin.Context, key string) (T, bool) {
	var zero T
	claims, exists := c.Get(key)
	if !exists {
		return zero, false
	}
	typed, ok := claims.(T)
	return typed, ok
}

// UserID retrieves user ID from Gin context.
func UserID(c *gin.Context) string {
	if v, exists := c.Get("user_id"); exists {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// shouldSkip checks if the Gin request path should skip authentication.
func shouldSkip(c *gin.Context, skipPaths []string) bool {
	path := c.Request.URL.Path
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
