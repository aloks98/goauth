package gin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aloks98/goauth/middleware"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// Mock implementations

type mockTokenValidator struct {
	claims interface{}
	err    error
}

func (m *mockTokenValidator) ValidateAccessToken(ctx context.Context, token string) (interface{}, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

type mockClaimsExtractor struct{}

func (m *mockClaimsExtractor) ExtractUserID(claims interface{}) string {
	if c, ok := claims.(map[string]string); ok {
		return c["sub"]
	}
	return ""
}

func (m *mockClaimsExtractor) ExtractPermissions(claims interface{}) []string {
	if c, ok := claims.(map[string]interface{}); ok {
		if perms, ok := c["permissions"].([]string); ok {
			return perms
		}
	}
	return nil
}

type mockPermissionChecker struct {
	hasPermission bool
	err           error
}

func (m *mockPermissionChecker) HasPermission(ctx context.Context, userID, permission string) (bool, error) {
	return m.hasPermission, m.err
}

type mockAPIKeyValidator struct {
	keyInfo *middleware.APIKeyInfo
	err     error
}

func (m *mockAPIKeyValidator) ValidateAPIKey(ctx context.Context, rawKey string) (*middleware.APIKeyInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.keyInfo, nil
}

// Tests

func TestGinAuthenticate_ValidToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	router := gin.New()
	router.Use(Authenticate(validator, extractor, nil))
	router.GET("/api/resource", func(c *gin.Context) {
		userID := UserID(c)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestGinAuthenticate_MissingToken(t *testing.T) {
	validator := &mockTokenValidator{}
	extractor := &mockClaimsExtractor{}

	router := gin.New()
	router.Use(Authenticate(validator, extractor, nil))
	router.GET("/api/resource", func(c *gin.Context) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestGinAuthenticate_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("invalid token"),
	}
	extractor := &mockClaimsExtractor{}

	router := gin.New()
	router.Use(Authenticate(validator, extractor, nil))
	router.GET("/api/resource", func(c *gin.Context) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestGinAuthenticate_SkipPath(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("should not be called"),
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("Authorization", "Bearer"),
		ErrorHandler:   DefaultErrorHandler,
		SkipPaths:      []string{"/health", "/public/*"},
	}

	router := gin.New()
	router.Use(Authenticate(validator, nil, cfg))
	router.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	router.GET("/public/*path", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Test exact match
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/health: expected status 200, got %d", w.Code)
	}

	// Test wildcard match
	req = httptest.NewRequest(http.MethodGet, "/public/assets/logo.png", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/public/*: expected status 200, got %d", w.Code)
	}
}

func TestGinRequirePermission_HasPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	router := gin.New()
	router.Use(Authenticate(validator, extractor, nil))
	router.Use(RequirePermission(checker, "users:read", nil))
	router.GET("/api/users", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestGinRequirePermission_NoPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: false}

	router := gin.New()
	router.Use(Authenticate(validator, extractor, nil))
	router.Use(RequirePermission(checker, "users:write", nil))
	router.POST("/api/users", func(c *gin.Context) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestGinAuthenticateAPIKey_Valid(t *testing.T) {
	validator := &mockAPIKeyValidator{
		keyInfo: &middleware.APIKeyInfo{
			ID:     "key-123",
			UserID: "user-456",
			Scopes: []string{"read:users"},
		},
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   DefaultErrorHandler,
	}

	router := gin.New()
	router.Use(AuthenticateAPIKey(validator, cfg))
	router.GET("/api/resource", func(c *gin.Context) {
		userID := UserID(c)
		if userID != "user-456" {
			t.Errorf("expected user ID 'user-456', got '%s'", userID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "sk_test_abc123")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestGinAuthenticateAPIKey_Invalid(t *testing.T) {
	validator := &mockAPIKeyValidator{
		err: errors.New("invalid API key"),
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   DefaultErrorHandler,
	}

	router := gin.New()
	router.Use(AuthenticateAPIKey(validator, cfg))
	router.GET("/api/resource", func(c *gin.Context) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestGinExtractFromQuery(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	cfg := &Config{
		TokenExtractor: ExtractFromQuery("token"),
		ErrorHandler:   DefaultErrorHandler,
	}

	router := gin.New()
	router.Use(Authenticate(validator, extractor, cfg))
	router.GET("/api/resource", func(c *gin.Context) {
		userID := UserID(c)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource?token=my-jwt-token", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestGinClaims(t *testing.T) {
	type CustomClaims struct {
		Sub      string `json:"sub"`
		TenantID string `json:"tenant_id"`
	}

	validator := &mockTokenValidator{
		claims: CustomClaims{Sub: "user123", TenantID: "tenant-abc"},
	}

	router := gin.New()
	router.Use(Authenticate(validator, nil, nil))
	router.GET("/api/resource", func(c *gin.Context) {
		claims, ok := Claims[CustomClaims](c, "claims")
		if !ok {
			t.Error("expected claims to be present")
			return
		}
		if claims.TenantID != "tenant-abc" {
			t.Errorf("expected tenant ID 'tenant-abc', got '%s'", claims.TenantID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}
