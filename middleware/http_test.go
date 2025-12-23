package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Mock implementations for testing

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

func TestAuthenticate_ValidToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	middleware := Authenticate(validator, extractor, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that user ID was set in context
		userID := GetUserID(r.Context())
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestAuthenticate_MissingToken(t *testing.T) {
	validator := &mockTokenValidator{}
	extractor := &mockClaimsExtractor{}

	middleware := Authenticate(validator, extractor, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	// No Authorization header
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("invalid token"),
	}
	extractor := &mockClaimsExtractor{}

	middleware := Authenticate(validator, extractor, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestAuthenticate_SkipPath(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("should not be called"),
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("Authorization", "Bearer"),
		ErrorHandler:   DefaultErrorHandler,
		SkipPaths:      []string{"/health", "/public/*"},
	}

	middleware := Authenticate(validator, nil, cfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test exact match
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/health: expected status 200, got %d", w.Code)
	}

	// Test wildcard match
	req = httptest.NewRequest(http.MethodGet, "/public/assets/logo.png", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/public/*: expected status 200, got %d", w.Code)
	}
}

func TestRequirePermission_HasPermission(t *testing.T) {
	checker := &mockPermissionChecker{hasPermission: true}

	middleware := RequirePermission(checker, "users:read", nil)

	// Set up context with user ID (as if Authenticate ran first)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	ctx := SetUserID(req.Context(), "user123")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestRequirePermission_NoPermission(t *testing.T) {
	checker := &mockPermissionChecker{hasPermission: false}

	middleware := RequirePermission(checker, "users:write", nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	ctx := SetUserID(req.Context(), "user123")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestAuthenticateAPIKey_Valid(t *testing.T) {
	validator := &mockAPIKeyValidator{
		keyInfo: &APIKeyInfo{
			ID:     "key-123",
			UserID: "user-456",
			Scopes: []string{"read:users"},
		},
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   DefaultErrorHandler,
	}

	middleware := AuthenticateAPIKey(validator, cfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyInfo := GetAPIKeyInfo(r.Context())
		if keyInfo == nil {
			t.Error("expected API key info in context")
			return
		}
		if keyInfo.UserID != "user-456" {
			t.Errorf("expected user ID 'user-456', got '%s'", keyInfo.UserID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "sk_test_abc123")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestAuthenticateAPIKey_Invalid(t *testing.T) {
	validator := &mockAPIKeyValidator{
		err: errors.New("invalid API key"),
	}

	cfg := &Config{
		TokenExtractor: ExtractFromHeader("X-API-Key", ""),
		ErrorHandler:   DefaultErrorHandler,
	}

	middleware := AuthenticateAPIKey(validator, cfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestRequireScope_HasScope(t *testing.T) {
	middleware := RequireScope("users:read", nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	ctx := SetAPIKeyInfo(req.Context(), &APIKeyInfo{
		ID:     "key-123",
		UserID: "user-456",
		Scopes: []string{"users:read", "users:write"},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestRequireScope_NoScope(t *testing.T) {
	middleware := RequireScope("admin:*", nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	ctx := SetAPIKeyInfo(req.Context(), &APIKeyInfo{
		ID:     "key-123",
		UserID: "user-456",
		Scopes: []string{"users:read"},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestRequireScope_EmptyScopes_FullAccess(t *testing.T) {
	middleware := RequireScope("anything:here", nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	ctx := SetAPIKeyInfo(req.Context(), &APIKeyInfo{
		ID:     "key-123",
		UserID: "user-456",
		Scopes: []string{}, // Empty = full access
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 (empty scopes = full access), got %d", w.Code)
	}
}

func TestOptionalAuthenticate_WithToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}

	middleware := OptionalAuthenticate(validator, extractor, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := GetUserID(r.Context())
		if userID != "user123" {
			t.Errorf("expected user ID 'user123', got '%s'", userID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestOptionalAuthenticate_WithoutToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: errors.New("should not be called"),
	}

	middleware := OptionalAuthenticate(validator, nil, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := GetUserID(r.Context())
		if userID != "" {
			t.Errorf("expected empty user ID, got '%s'", userID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	// No Authorization header
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

// Example: Full middleware chain test
func TestMiddlewareChain(t *testing.T) {
	validator := &mockTokenValidator{
		claims: map[string]string{"sub": "user123"},
	}
	extractor := &mockClaimsExtractor{}
	checker := &mockPermissionChecker{hasPermission: true}

	// Chain: Authenticate -> RequirePermission -> Handler
	authMiddleware := Authenticate(validator, extractor, nil)
	permMiddleware := RequirePermission(checker, "posts:read", nil)

	handler := authMiddleware(permMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := GetUserID(r.Context())
		w.Write([]byte("Hello, " + userID))
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/posts", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if w.Body.String() != "Hello, user123" {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}
