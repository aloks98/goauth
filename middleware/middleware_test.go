package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractFromHeader(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		scheme   string
		value    string
		expected string
	}{
		{
			name:     "Bearer token",
			header:   "Authorization",
			scheme:   "Bearer",
			value:    "Bearer token123",
			expected: "token123",
		},
		{
			name:     "Bearer token lowercase",
			header:   "Authorization",
			scheme:   "Bearer",
			value:    "bearer token123",
			expected: "token123",
		},
		{
			name:     "No scheme",
			header:   "X-API-Key",
			scheme:   "",
			value:    "apikey123",
			expected: "apikey123",
		},
		{
			name:     "Empty header",
			header:   "Authorization",
			scheme:   "Bearer",
			value:    "",
			expected: "",
		},
		{
			name:     "Wrong scheme",
			header:   "Authorization",
			scheme:   "Bearer",
			value:    "Basic dXNlcjpwYXNz",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := ExtractFromHeader(tt.header, tt.scheme)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.value != "" {
				req.Header.Set(tt.header, tt.value)
			}

			got := extractor(req)
			if got != tt.expected {
				t.Errorf("ExtractFromHeader() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractFromQuery(t *testing.T) {
	extractor := ExtractFromQuery("token")

	req := httptest.NewRequest(http.MethodGet, "/?token=abc123", nil)
	got := extractor(req)
	if got != "abc123" {
		t.Errorf("ExtractFromQuery() = %q, want %q", got, "abc123")
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	got = extractor(req)
	if got != "" {
		t.Errorf("ExtractFromQuery() with missing param = %q, want empty", got)
	}
}

func TestExtractFromCookie(t *testing.T) {
	extractor := ExtractFromCookie("auth")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: "cookie123"})

	got := extractor(req)
	if got != "cookie123" {
		t.Errorf("ExtractFromCookie() = %q, want %q", got, "cookie123")
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	got = extractor(req)
	if got != "" {
		t.Errorf("ExtractFromCookie() with missing cookie = %q, want empty", got)
	}
}

func TestChainExtractors(t *testing.T) {
	headerExtractor := ExtractFromHeader("Authorization", "Bearer")
	queryExtractor := ExtractFromQuery("token")
	chained := ChainExtractors(headerExtractor, queryExtractor)

	// Header takes precedence
	req := httptest.NewRequest(http.MethodGet, "/?token=query", nil)
	req.Header.Set("Authorization", "Bearer header")
	got := chained(req)
	if got != "header" {
		t.Errorf("ChainExtractors() header precedence = %q, want %q", got, "header")
	}

	// Falls back to query
	req = httptest.NewRequest(http.MethodGet, "/?token=query", nil)
	got = chained(req)
	if got != "query" {
		t.Errorf("ChainExtractors() fallback = %q, want %q", got, "query")
	}

	// Both empty
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	got = chained(req)
	if got != "" {
		t.Errorf("ChainExtractors() empty = %q, want empty", got)
	}
}

func TestShouldSkip(t *testing.T) {
	skipPaths := []string{"/health", "/public/*", "/api/*/docs"}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/public/file.txt", true},
		{"/public/dir/file.txt", true},
		{"/api/v1/docs", true},
		{"/api/v2/docs", true},
		{"/api/users", false},
		{"/private", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			got := ShouldSkip(req, skipPaths)
			if got != tt.expected {
				t.Errorf("ShouldSkip(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern  string
		path     string
		expected bool
	}{
		{"/exact", "/exact", true},
		{"/exact", "/other", false},
		{"/prefix/*", "/prefix/anything", true},
		{"/prefix/*", "/prefix/a/b", true},
		{"/prefix/*", "/other/path", false},
		{"/api/*/users", "/api/v1/users", true},
		{"/api/*/users", "/api/v2/users", true},
		{"/api/*/users", "/api/v1/posts", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"->"+tt.path, func(t *testing.T) {
			got := matchPath(tt.pattern, tt.path)
			if got != tt.expected {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.expected)
			}
		})
	}
}

func TestErrorToHTTPStatus(t *testing.T) {
	tests := []struct {
		errMsg   string
		expected int
	}{
		{"token expired", http.StatusUnauthorized},
		{"invalid token", http.StatusUnauthorized},
		{"token blacklisted", http.StatusUnauthorized},
		{"missing token", http.StatusUnauthorized},
		{"permission denied", http.StatusForbidden},
		{"token revoked", http.StatusUnauthorized},
		{"resource not found", http.StatusNotFound},
		{"unknown error", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.errMsg, func(t *testing.T) {
			err := &testError{msg: tt.errMsg}
			got := ErrorToHTTPStatus(err)
			if got != tt.expected {
				t.Errorf("ErrorToHTTPStatus(%q) = %d, want %d", tt.errMsg, got, tt.expected)
			}
		})
	}

	// Test nil error
	if got := ErrorToHTTPStatus(nil); got != http.StatusOK {
		t.Errorf("ErrorToHTTPStatus(nil) = %d, want %d", got, http.StatusOK)
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Test SetClaims/GetClaims
	claims := map[string]string{"sub": "user123"}
	ctx = SetClaims(ctx, claims)
	gotClaims := GetClaims(ctx)
	if gotClaims == nil {
		t.Error("GetClaims() returned nil")
	}

	// Test SetUserID/GetUserID
	ctx = SetUserID(ctx, "user123")
	if got := GetUserID(ctx); got != "user123" {
		t.Errorf("GetUserID() = %q, want %q", got, "user123")
	}

	// Test SetPermissions/GetPermissions
	perms := []string{"read", "write"}
	ctx = SetPermissions(ctx, perms)
	gotPerms := GetPermissions(ctx)
	if len(gotPerms) != 2 {
		t.Errorf("GetPermissions() len = %d, want 2", len(gotPerms))
	}

	// Test SetAPIKeyInfo/GetAPIKeyInfo
	keyInfo := &APIKeyInfo{ID: "key1", UserID: "user1", Scopes: []string{"read"}}
	ctx = SetAPIKeyInfo(ctx, keyInfo)
	gotKeyInfo := GetAPIKeyInfo(ctx)
	if gotKeyInfo == nil || gotKeyInfo.ID != "key1" {
		t.Error("GetAPIKeyInfo() returned wrong value")
	}

	// Test empty context
	emptyCtx := context.Background()
	if got := GetUserID(emptyCtx); got != "" {
		t.Errorf("GetUserID(empty) = %q, want empty", got)
	}
	if got := GetPermissions(emptyCtx); got != nil {
		t.Error("GetPermissions(empty) should be nil")
	}
	if got := GetAPIKeyInfo(emptyCtx); got != nil {
		t.Error("GetAPIKeyInfo(empty) should be nil")
	}
}

func TestMatchScope(t *testing.T) {
	tests := []struct {
		have     string
		want     string
		expected bool
	}{
		{"*", "anything", true},
		{"read", "read", true},
		{"read", "write", false},
		{"users:*", "users:read", true},
		{"users:*", "users:write", true},
		{"users:*", "posts:read", false},
		{"*:read", "users:read", true},
		{"*:read", "posts:read", true},
		{"*:read", "users:write", false},
	}

	for _, tt := range tests {
		t.Run(tt.have+"->"+tt.want, func(t *testing.T) {
			got := matchScope(tt.have, tt.want)
			if got != tt.expected {
				t.Errorf("matchScope(%q, %q) = %v, want %v", tt.have, tt.want, got, tt.expected)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.TokenExtractor == nil {
		t.Error("DefaultConfig().TokenExtractor is nil")
	}
	if cfg.ErrorHandler == nil {
		t.Error("DefaultConfig().ErrorHandler is nil")
	}
	if cfg.ClaimsContextKey != ClaimsKey {
		t.Errorf("DefaultConfig().ClaimsContextKey = %v, want %v", cfg.ClaimsContextKey, ClaimsKey)
	}
}

func TestDefaultErrorHandler(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	DefaultErrorHandler(w, r, ErrMissingToken)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("DefaultErrorHandler status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
