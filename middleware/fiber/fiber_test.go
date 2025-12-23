package fiber

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

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

func TestFiberAuthenticate_ValidToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	app := fiber.New()
	app.Use(Authenticate(validator, extractor, nil))
	app.Get("/api/resource", func(c *fiber.Ctx) error {
		userID := UserID(c)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestFiberAuthenticate_MissingToken(t *testing.T) {
	validator := &mockTokenValidator{}
	extractor := &mockClaimsExtractor{}

	app := fiber.New()
	app.Use(Authenticate(validator, extractor, nil))
	app.Get("/api/resource", func(c *fiber.Ctx) error {
		t.Error("handler should not be called")
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestFiberAuthenticate_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("invalid token"),
	}
	extractor := &mockClaimsExtractor{}

	app := fiber.New()
	app.Use(Authenticate(validator, extractor, nil))
	app.Get("/api/resource", func(c *fiber.Ctx) error {
		t.Error("handler should not be called")
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestFiberAuthenticate_SkipPath(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("should not be called"),
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("Authorization", "Bearer"),
		ErrorHandler:   DefaultErrorHandler,
		SkipPaths:      []string{"/health", "/public/*"},
	}

	app := fiber.New()
	app.Use(Authenticate(validator, nil, cfg))
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	app.Get("/public/*", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Test exact match
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health: expected status 200, got %d", resp.StatusCode)
	}

	// Test wildcard match
	req = httptest.NewRequest(http.MethodGet, "/public/assets/logo.png", nil)
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/public/*: expected status 200, got %d", resp.StatusCode)
	}
}

func TestFiberRequirePermission_HasPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	app := fiber.New()
	app.Use(Authenticate(validator, extractor, nil))
	app.Use(RequirePermission(checker, "users:read", nil))
	app.Get("/api/users", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestFiberRequirePermission_NoPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: false}

	app := fiber.New()
	app.Use(Authenticate(validator, extractor, nil))
	app.Use(RequirePermission(checker, "users:write", nil))
	app.Post("/api/users", func(c *fiber.Ctx) error {
		t.Error("handler should not be called")
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", resp.StatusCode)
	}
}

func TestFiberAuthenticateAPIKey_Valid(t *testing.T) {
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

	app := fiber.New()
	app.Use(AuthenticateAPIKey(validator, cfg))
	app.Get("/api/resource", func(c *fiber.Ctx) error {
		userID := UserID(c)
		if userID != "user-456" {
			t.Errorf("expected user ID 'user-456', got '%s'", userID)
		}
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "sk_test_abc123")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestFiberAuthenticateAPIKey_Invalid(t *testing.T) {
	validator := &mockAPIKeyValidator{
		err: errors.New("invalid API key"),
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   DefaultErrorHandler,
	}

	app := fiber.New()
	app.Use(AuthenticateAPIKey(validator, cfg))
	app.Get("/api/resource", func(c *fiber.Ctx) error {
		t.Error("handler should not be called")
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "invalid-key")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestFiberExtractFromQuery(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	cfg := &Config{
		TokenExtractor: ExtractFromQuery("token"),
		ErrorHandler:   DefaultErrorHandler,
	}

	app := fiber.New()
	app.Use(Authenticate(validator, extractor, cfg))
	app.Get("/api/resource", func(c *fiber.Ctx) error {
		userID := UserID(c)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource?token=my-jwt-token", nil)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestFiberClaims(t *testing.T) {
	type CustomClaims struct {
		Sub      string `json:"sub"`
		TenantID string `json:"tenant_id"`
	}

	validator := &mockTokenValidator{
		claims: CustomClaims{Sub: "user123", TenantID: "tenant-abc"},
	}

	app := fiber.New()
	app.Use(Authenticate(validator, nil, nil))
	app.Get("/api/resource", func(c *fiber.Ctx) error {
		claims, ok := Claims[CustomClaims](c, "claims")
		if !ok {
			t.Error("expected claims to be present")
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		if claims.TenantID != "tenant-abc" {
			t.Errorf("expected tenant ID 'tenant-abc', got '%s'", claims.TenantID)
		}
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestFiberExtractFromCookie(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	cfg := &Config{
		TokenExtractor: ExtractFromCookie("auth_token"),
		ErrorHandler:   DefaultErrorHandler,
	}

	app := fiber.New()
	app.Use(Authenticate(validator, extractor, cfg))
	app.Get("/api/resource", func(c *fiber.Ctx) error {
		userID := UserID(c)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: "my-jwt-token",
	})

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestFiberMiddlewareChain(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	app := fiber.New()
	app.Use(Authenticate(validator, extractor, nil))
	app.Use(RequirePermission(checker, "posts:read", nil))
	app.Get("/api/posts", func(c *fiber.Ctx) error {
		userID := UserID(c)
		return c.SendString("Hello, " + userID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/posts", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Hello, user123" {
		t.Errorf("unexpected body: %s", body)
	}
}
