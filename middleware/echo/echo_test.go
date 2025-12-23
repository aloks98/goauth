package echo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/aloks98/goauth/middleware"
)

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

func TestEchoAuthenticate_ValidToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	e := echo.New()
	e.Use(Authenticate(validator, extractor, nil))
	e.GET("/api/resource", func(c echo.Context) error {
		userID := UserID(c)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestEchoAuthenticate_MissingToken(t *testing.T) {
	validator := &mockTokenValidator{}
	extractor := &mockClaimsExtractor{}

	e := echo.New()
	e.Use(Authenticate(validator, extractor, nil))
	e.GET("/api/resource", func(c echo.Context) error {
		t.Error("handler should not be called")
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestEchoAuthenticate_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("invalid token"),
	}
	extractor := &mockClaimsExtractor{}

	e := echo.New()
	e.Use(Authenticate(validator, extractor, nil))
	e.GET("/api/resource", func(c echo.Context) error {
		t.Error("handler should not be called")
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestEchoAuthenticate_SkipPath(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("should not be called"),
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("Authorization", "Bearer"),
		ErrorHandler:   DefaultErrorHandler,
		SkipPaths:      []string{"/health", "/public/*"},
	}

	e := echo.New()
	e.Use(Authenticate(validator, nil, cfg))
	e.GET("/health", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	e.GET("/public/*", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	// Test exact match
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/health: expected status 200, got %d", rec.Code)
	}

	// Test wildcard match
	req = httptest.NewRequest(http.MethodGet, "/public/assets/logo.png", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/public/*: expected status 200, got %d", rec.Code)
	}
}

func TestEchoRequirePermission_HasPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	e := echo.New()
	e.Use(Authenticate(validator, extractor, nil))
	e.Use(RequirePermission(checker, "users:read", nil))
	e.GET("/api/users", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestEchoRequirePermission_NoPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: false}

	e := echo.New()
	e.Use(Authenticate(validator, extractor, nil))
	e.Use(RequirePermission(checker, "users:write", nil))
	e.POST("/api/users", func(c echo.Context) error {
		t.Error("handler should not be called")
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestEchoAuthenticateAPIKey_Valid(t *testing.T) {
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

	e := echo.New()
	e.Use(AuthenticateAPIKey(validator, cfg))
	e.GET("/api/resource", func(c echo.Context) error {
		userID := UserID(c)
		if userID != "user-456" {
			t.Errorf("expected user ID 'user-456', got '%s'", userID)
		}
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "sk_test_abc123")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestEchoAuthenticateAPIKey_Invalid(t *testing.T) {
	validator := &mockAPIKeyValidator{
		err: errors.New("invalid API key"),
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   DefaultErrorHandler,
	}

	e := echo.New()
	e.Use(AuthenticateAPIKey(validator, cfg))
	e.GET("/api/resource", func(c echo.Context) error {
		t.Error("handler should not be called")
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestEchoExtractFromQuery(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	cfg := &Config{
		TokenExtractor: ExtractFromQuery("token"),
		ErrorHandler:   DefaultErrorHandler,
	}

	e := echo.New()
	e.Use(Authenticate(validator, extractor, cfg))
	e.GET("/api/resource", func(c echo.Context) error {
		userID := UserID(c)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource?token=my-jwt-token", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestEchoClaims(t *testing.T) {
	type CustomClaims struct {
		Sub      string `json:"sub"`
		TenantID string `json:"tenant_id"`
	}

	validator := &mockTokenValidator{
		claims: CustomClaims{Sub: "user123", TenantID: "tenant-abc"},
	}

	e := echo.New()
	e.Use(Authenticate(validator, nil, nil))
	e.GET("/api/resource", func(c echo.Context) error {
		claims, ok := Claims[CustomClaims](c, "claims")
		if !ok {
			t.Error("expected claims to be present")
			return c.NoContent(http.StatusInternalServerError)
		}
		if claims.TenantID != "tenant-abc" {
			t.Errorf("expected tenant ID 'tenant-abc', got '%s'", claims.TenantID)
		}
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}
