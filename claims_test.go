package goauth

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestStandardClaims_GetStandardClaims(t *testing.T) {
	claims := &StandardClaims{
		UserID:            "user123",
		JTI:               "jti456",
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(time.Hour).Unix(),
		PermissionVersion: 1,
	}

	got := claims.GetStandardClaims()
	if got != claims {
		t.Error("GetStandardClaims should return pointer to self")
	}
}

func TestStandardClaims_GetUserID(t *testing.T) {
	claims := &StandardClaims{UserID: "user123"}
	if got := claims.GetUserID(); got != "user123" {
		t.Errorf("GetUserID() = %q, want %q", got, "user123")
	}
}

func TestStandardClaims_GetJTI(t *testing.T) {
	claims := &StandardClaims{JTI: "jti456"}
	if got := claims.GetJTI(); got != "jti456" {
		t.Errorf("GetJTI() = %q, want %q", got, "jti456")
	}
}

func TestStandardClaims_GetIssuedAt(t *testing.T) {
	now := time.Now()
	claims := &StandardClaims{IssuedAt: now.Unix()}
	got := claims.GetIssuedAt()
	if got.Unix() != now.Unix() {
		t.Errorf("GetIssuedAt() = %v, want %v", got.Unix(), now.Unix())
	}
}

func TestStandardClaims_GetExpiresAt(t *testing.T) {
	future := time.Now().Add(time.Hour)
	claims := &StandardClaims{ExpiresAt: future.Unix()}
	got := claims.GetExpiresAt()
	if got.Unix() != future.Unix() {
		t.Errorf("GetExpiresAt() = %v, want %v", got.Unix(), future.Unix())
	}
}

func TestStandardClaims_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt int64
		expected  bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(time.Hour).Unix(),
			expected:  false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-time.Hour).Unix(),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &StandardClaims{ExpiresAt: tt.expiresAt}
			if got := claims.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStandardClaims_IsNotYetValid(t *testing.T) {
	tests := []struct {
		name     string
		issuedAt int64
		expected bool
	}{
		{
			name:     "valid",
			issuedAt: time.Now().Add(-time.Hour).Unix(),
			expected: false,
		},
		{
			name:     "not yet valid",
			issuedAt: time.Now().Add(time.Hour).Unix(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &StandardClaims{IssuedAt: tt.issuedAt}
			if got := claims.IsNotYetValid(); got != tt.expected {
				t.Errorf("IsNotYetValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStandardClaims_TimeUntilExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour)
	claims := &StandardClaims{ExpiresAt: future.Unix()}

	ttl := claims.TimeUntilExpiry()
	if ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Errorf("TimeUntilExpiry() = %v, expected ~1 hour", ttl)
	}
}

func TestStandardClaims_JSON(t *testing.T) {
	claims := &StandardClaims{
		UserID:            "user123",
		JTI:               "jti456",
		IssuedAt:          1234567890,
		ExpiresAt:         1234571490,
		PermissionVersion: 5,
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded StandardClaims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.UserID != claims.UserID {
		t.Errorf("UserID = %q, want %q", decoded.UserID, claims.UserID)
	}
	if decoded.JTI != claims.JTI {
		t.Errorf("JTI = %q, want %q", decoded.JTI, claims.JTI)
	}
	if decoded.PermissionVersion != claims.PermissionVersion {
		t.Errorf("PermissionVersion = %d, want %d", decoded.PermissionVersion, claims.PermissionVersion)
	}
}

// CustomClaims demonstrates embedding StandardClaims
type CustomClaims struct {
	StandardClaims
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

func TestCustomClaims_Embedding(t *testing.T) {
	claims := &CustomClaims{
		StandardClaims: StandardClaims{
			UserID:    "user123",
			JTI:       "jti456",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		TenantID: "tenant789",
		Role:     "admin",
	}

	// Should satisfy Claims interface
	var _ Claims = claims

	// GetStandardClaims should work
	std := claims.GetStandardClaims()
	if std.UserID != "user123" {
		t.Errorf("UserID = %q, want %q", std.UserID, "user123")
	}
}

// Mock context for testing ClaimsFromContext
type mockContext struct {
	values map[any]any
}

func (m *mockContext) Value(key any) any {
	return m.values[key]
}

func TestClaimsFromContext(t *testing.T) {
	type ctxKey string
	const claimsKey ctxKey = "claims"

	claims := &CustomClaims{
		StandardClaims: StandardClaims{UserID: "user123"},
		TenantID:       "tenant456",
	}

	ctx := &mockContext{values: map[any]any{claimsKey: claims}}

	got := ClaimsFromContext[*CustomClaims](ctx, claimsKey)
	if got == nil {
		t.Fatal("ClaimsFromContext returned nil")
	}
	if got.UserID != "user123" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user123")
	}
	if got.TenantID != "tenant456" {
		t.Errorf("TenantID = %q, want %q", got.TenantID, "tenant456")
	}
}

func TestClaimsFromContext_Missing(t *testing.T) {
	ctx := context.Background()
	got := ClaimsFromContext[*CustomClaims](ctx, "missing")
	if got != nil {
		t.Error("ClaimsFromContext should return nil for missing key")
	}
}

func TestClaimsFromContext_WrongType(t *testing.T) {
	type ctxKey string
	const claimsKey ctxKey = "claims"

	ctx := &mockContext{values: map[any]any{claimsKey: "not a claims type"}}

	got := ClaimsFromContext[*CustomClaims](ctx, claimsKey)
	if got != nil {
		t.Error("ClaimsFromContext should return nil for wrong type")
	}
}
