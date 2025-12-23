package chi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

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

func (m *mockPermissionChecker) HasAllPermissions(ctx context.Context, userID string, permissions []string) (bool, error) {
	return m.hasPermission, m.err
}

func (m *mockPermissionChecker) HasAnyPermission(ctx context.Context, userID string, permissions []string) (bool, error) {
	return m.hasPermission, m.err
}

type mockAPIKeyValidator struct {
	keyInfo *APIKeyInfo
	err     error
}

func (m *mockAPIKeyValidator) ValidateAPIKey(ctx context.Context, rawKey string) (*APIKeyInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.keyInfo, nil
}

// Tests

func TestChiAuthenticate_ValidToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Get("/api/resource", func(w http.ResponseWriter, req *http.Request) {
		userID := UserID(req)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiAuthenticate_MissingToken(t *testing.T) {
	validator := &mockTokenValidator{}
	extractor := &mockClaimsExtractor{}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Get("/api/resource", func(w http.ResponseWriter, req *http.Request) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestChiAuthenticate_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("invalid token"),
	}
	extractor := &mockClaimsExtractor{}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Get("/api/resource", func(w http.ResponseWriter, req *http.Request) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestChiRequirePermission_HasPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Use(RequirePermission(checker, "users:read", nil))
	r.Get("/api/users", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiRequirePermission_NoPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: false}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Use(RequirePermission(checker, "users:write", nil))
	r.Post("/api/users", func(w http.ResponseWriter, req *http.Request) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestChiRequireAllPermissions(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Use(RequireAllPermissions(checker, []string{"users:read", "users:write"}, nil))
	r.Put("/api/users/1", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPut, "/api/users/1", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiRequireAnyPermission(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Use(RequireAnyPermission(checker, []string{"users:read", "admin:*"}, nil))
	r.Get("/api/users", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiAuthenticateAPIKey_Valid(t *testing.T) {
	validator := &mockAPIKeyValidator{
		keyInfo: &APIKeyInfo{
			ID:     "key-123",
			UserID: "user-456",
			Scopes: []string{"read:users"},
		},
	}

	cfg := &Config{
		TokenExtractor: middleware.ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   middleware.DefaultErrorHandler,
	}

	r := chi.NewRouter()
	r.Use(AuthenticateAPIKey(validator, cfg))
	r.Get("/api/resource", func(w http.ResponseWriter, req *http.Request) {
		keyInfo := GetAPIKeyInfo(req)
		if keyInfo == nil {
			t.Error("expected API key info in context")
			return
		}
		if keyInfo.UserID != "user-456" {
			t.Errorf("expected user ID 'user-456', got '%s'", keyInfo.UserID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "sk_test_abc123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiAuthenticateAPIKey_Invalid(t *testing.T) {
	validator := &mockAPIKeyValidator{
		err: errors.New("invalid API key"),
	}

	cfg := &Config{
		TokenExtractor: middleware.ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   middleware.DefaultErrorHandler,
	}

	r := chi.NewRouter()
	r.Use(AuthenticateAPIKey(validator, cfg))
	r.Get("/api/resource", func(w http.ResponseWriter, req *http.Request) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestChiRequireScope(t *testing.T) {
	validator := &mockAPIKeyValidator{
		keyInfo: &APIKeyInfo{
			ID:     "key-123",
			UserID: "user-456",
			Scopes: []string{"users:read", "users:write"},
		},
	}

	cfg := &Config{
		TokenExtractor: middleware.ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   middleware.DefaultErrorHandler,
	}

	r := chi.NewRouter()
	r.Use(AuthenticateAPIKey(validator, cfg))
	r.Use(RequireScope("users:read", nil))
	r.Get("/api/users", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-API-Key", "sk_test_abc123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiURLParam(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Get("/api/users/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := URLParam(req, "id")
		if id != "42" {
			t.Errorf("expected id '42', got '%s'", id)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users/42", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiClaims(t *testing.T) {
	type CustomClaims struct {
		Sub      string `json:"sub"`
		TenantID string `json:"tenant_id"`
	}

	validator := &mockTokenValidator{
		claims: CustomClaims{Sub: "user123", TenantID: "tenant-abc"},
	}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, nil, nil))
	r.Get("/api/resource", func(w http.ResponseWriter, req *http.Request) {
		claims, ok := Claims[CustomClaims](req)
		if !ok {
			t.Error("expected claims to be present")
			return
		}
		if claims.TenantID != "tenant-abc" {
			t.Errorf("expected tenant ID 'tenant-abc', got '%s'", claims.TenantID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiMiddlewareChain(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	r := chi.NewRouter()
	r.Use(Authenticate(validator, extractor, nil))
	r.Use(RequirePermission(checker, "posts:read", nil))
	r.Get("/api/posts", func(w http.ResponseWriter, req *http.Request) {
		userID := UserID(req)
		w.Write([]byte("Hello, " + userID))
	})

	req := httptest.NewRequest(http.MethodGet, "/api/posts", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if w.Body.String() != "Hello, user123" {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestChiOptionalAuthenticate_WithToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	r := chi.NewRouter()
	r.Use(OptionalAuthenticate(validator, extractor, nil))
	r.Get("/api/resource", func(w http.ResponseWriter, req *http.Request) {
		userID := UserID(req)
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestChiOptionalAuthenticate_WithoutToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("should not be called"),
	}

	r := chi.NewRouter()
	r.Use(OptionalAuthenticate(validator, nil, nil))
	r.Get("/api/resource", func(w http.ResponseWriter, req *http.Request) {
		userID := UserID(req)
		if userID != "" {
			t.Errorf("expected empty user ID, got '%s'", userID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}
