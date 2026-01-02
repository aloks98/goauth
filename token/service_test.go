package token

import (
	"context"
	"testing"
	"time"

	"github.com/aloks98/goauth/internal/testutil"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	s := testutil.SetupPostgres(t)
	cfg := &Config{
		Secret:          "this-is-a-32-character-secret!!!", // 33 chars
		SigningMethod:   "HS256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		ClockSkew:       30 * time.Second,
	}
	return NewService(cfg, s)
}

func TestNewService(t *testing.T) {
	tests := []struct {
		name          string
		signingMethod string
	}{
		{"HS256", "HS256"},
		{"HS384", "HS384"},
		{"HS512", "HS512"},
		{"RS256", "RS256"},
		{"RS384", "RS384"},
		{"RS512", "RS512"},
		{"default", "unknown"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testutil.SetupPostgres(t)
			cfg := &Config{
				Secret:          "this-is-a-32-character-secret!!!",
				SigningMethod:   tt.signingMethod,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
			}
			svc := NewService(cfg, s)
			if svc == nil {
				t.Fatal("expected service to be created")
			}
		})
	}
}

func TestGenerateTokenPair(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, "user-123", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("expected access token to be non-empty")
	}
	if pair.RefreshToken == "" {
		t.Error("expected refresh token to be non-empty")
	}
	if pair.TokenType != "Bearer" {
		t.Errorf("expected token type Bearer, got %s", pair.TokenType)
	}
	if pair.ExpiresIn != 900 { // 15 minutes in seconds
		t.Errorf("expected expires_in 900, got %d", pair.ExpiresIn)
	}
	if pair.ExpiresAt.Before(time.Now()) {
		t.Error("expected expires_at to be in the future")
	}
}

func TestGenerateTokenPairWithCustomClaims(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	customClaims := map[string]any{
		"tenant_id": "tenant-abc",
		"role":      "admin",
	}

	pair, err := svc.GenerateTokenPair(ctx, "user-123", customClaims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Validate the access token to check claims
	claims, err := svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("failed to validate access token: %v", err)
	}

	if claims.Custom["tenant_id"] != "tenant-abc" {
		t.Errorf("expected tenant_id tenant-abc, got %v", claims.Custom["tenant_id"])
	}
	if claims.Custom["role"] != "admin" {
		t.Errorf("expected role admin, got %v", claims.Custom["role"])
	}
}

func TestValidateAccessToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, "user-456", nil)
	if err != nil {
		t.Fatalf("unexpected error generating token pair: %v", err)
	}

	claims, err := svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims.UserID != "user-456" {
		t.Errorf("expected user ID user-456, got %s", claims.UserID)
	}
	if claims.JTI == "" {
		t.Error("expected JTI to be non-empty")
	}
}

func TestValidateAccessToken_Invalid(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"invalid", "not-a-jwt"},
		{"malformed", "a.b.c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateAccessToken(ctx, tt.token)
			if err == nil {
				t.Error("expected error for invalid token")
			}
		})
	}
}

func TestValidateAccessToken_Blacklisted(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, "user-789", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First validation should succeed
	claims, err := svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Blacklist the token
	if err := svc.AddToBlacklist(ctx, claims.JTI, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("failed to blacklist: %v", err)
	}

	// Second validation should fail
	_, err = svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != ErrTokenBlacklisted {
		t.Errorf("expected ErrTokenBlacklisted, got %v", err)
	}
}

func TestRefreshTokens(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Generate initial token pair
	pair1, err := svc.GenerateTokenPair(ctx, "user-123", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Refresh tokens
	pair2, err := svc.RefreshTokens(ctx, pair1.RefreshToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pair2.AccessToken == "" {
		t.Error("expected new access token")
	}
	if pair2.RefreshToken == "" {
		t.Error("expected new refresh token")
	}
	if pair2.RefreshToken == pair1.RefreshToken {
		t.Error("expected new refresh token to be different from old")
	}
}

func TestRefreshTokens_InvalidToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no_dot", "nodottoken"},
		{"invalid_jti", "invalid-jti.randompart"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.RefreshTokens(ctx, tt.token)
			if err == nil {
				t.Error("expected error for invalid refresh token")
			}
		})
	}
}

func TestRefreshTokens_TokenReuse(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Generate initial token pair
	pair1, err := svc.GenerateTokenPair(ctx, "user-123", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First refresh should succeed
	_, err = svc.RefreshTokens(ctx, pair1.RefreshToken)
	if err != nil {
		t.Fatalf("unexpected error on first refresh: %v", err)
	}

	// Second refresh with same token should fail (token reuse detection)
	_, err = svc.RefreshTokens(ctx, pair1.RefreshToken)
	if err != ErrRefreshTokenReused {
		t.Errorf("expected ErrRefreshTokenReused, got %v", err)
	}
}

func TestRevokeAccessToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, "user-123", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Revoke the access token
	if err := svc.RevokeAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("failed to revoke: %v", err)
	}

	// Token should now be invalid
	_, err = svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != ErrTokenBlacklisted {
		t.Errorf("expected ErrTokenBlacklisted, got %v", err)
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Generate refresh token
	result, err := svc.GenerateRefreshToken(ctx, "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Revoke by JTI
	if err := svc.RevokeRefreshToken(ctx, result.JTI); err != nil {
		t.Fatalf("failed to revoke: %v", err)
	}

	// Validate should now fail
	_, err = svc.ValidateRefreshToken(ctx, result.Token)
	if err != ErrRefreshTokenReused {
		t.Errorf("expected ErrRefreshTokenReused (revoked), got %v", err)
	}
}

func TestRevokeAllUserTokens(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Generate multiple tokens for same user
	pair1, _ := svc.GenerateTokenPair(ctx, "user-123", nil)
	pair2, _ := svc.GenerateTokenPair(ctx, "user-123", nil)

	// Revoke all
	if err := svc.RevokeAllUserTokens(ctx, "user-123"); err != nil {
		t.Fatalf("failed to revoke all: %v", err)
	}

	// Both refresh tokens should be invalid
	_, err := svc.RefreshTokens(ctx, pair1.RefreshToken)
	if err == nil {
		t.Error("expected error for revoked token 1")
	}
	_, err = svc.RefreshTokens(ctx, pair2.RefreshToken)
	if err == nil {
		t.Error("expected error for revoked token 2")
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	result, err := svc.GenerateRefreshToken(ctx, "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Token == "" {
		t.Error("expected token to be non-empty")
	}
	if result.JTI == "" {
		t.Error("expected JTI to be non-empty")
	}
	if result.FamilyID == "" {
		t.Error("expected FamilyID to be non-empty")
	}
	if result.ExpiresAt.Before(time.Now()) {
		t.Error("expected expires_at to be in the future")
	}
}

func TestValidateRefreshToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	result, err := svc.GenerateRefreshToken(ctx, "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	storedToken, err := svc.ValidateRefreshToken(ctx, result.Token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if storedToken.UserID != "user-123" {
		t.Errorf("expected user ID user-123, got %s", storedToken.UserID)
	}
	if storedToken.FamilyID != result.FamilyID {
		t.Errorf("family ID mismatch")
	}
}

func TestClaims(t *testing.T) {
	claims := &Claims{
		UserID: "user-123",
		JTI:    "jti-456",
	}

	if claims.GetUserID() != "user-123" {
		t.Errorf("expected user ID user-123, got %s", claims.GetUserID())
	}
	if claims.GetJTI() != "jti-456" {
		t.Errorf("expected JTI jti-456, got %s", claims.GetJTI())
	}
}

func TestIsBlacklisted(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Not blacklisted initially
	blacklisted, err := svc.IsBlacklisted(ctx, "some-jti")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blacklisted {
		t.Error("expected not blacklisted")
	}

	// Add to blacklist
	if err := svc.AddToBlacklist(ctx, "some-jti", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("failed to blacklist: %v", err)
	}

	// Should be blacklisted now
	blacklisted, err = svc.IsBlacklisted(ctx, "some-jti")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !blacklisted {
		t.Error("expected blacklisted")
	}
}

func TestInvalidatePermissionCache(t *testing.T) {
	svc := newTestService(t)

	// This should not panic
	svc.InvalidatePermissionCache("user-123")
}

func TestRevokeTokenFamily(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Generate a token to get a family ID
	result, err := svc.GenerateRefreshToken(ctx, "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Revoke the family
	if err := svc.RevokeTokenFamily(ctx, result.FamilyID); err != nil {
		t.Fatalf("failed to revoke family: %v", err)
	}

	// Token should be invalid now
	_, err = svc.ValidateRefreshToken(ctx, result.Token)
	if err == nil {
		t.Error("expected error for revoked family")
	}
}
