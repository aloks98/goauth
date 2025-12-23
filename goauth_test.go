package goauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aloks98/goauth/store/memory"
)

// TestClaims is a custom claims type for testing
type TestClaims struct {
	StandardClaims
	Role string `json:"role"`
}

func TestNew_Success(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	if auth.config == nil {
		t.Error("config should not be nil")
	}
	if auth.store == nil {
		t.Error("store should not be nil")
	}
}

func TestNew_WithoutStore(t *testing.T) {
	_, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
	)
	if !errors.Is(err, ErrStoreRequired) {
		t.Errorf("New() error = %v, want %v", err, ErrStoreRequired)
	}
}

func TestNew_WithoutSecret(t *testing.T) {
	store := memory.New()
	defer store.Close()

	_, err := New[*TestClaims](
		WithStore(store),
	)
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("New() error = %v, want %v", err, ErrConfigInvalid)
	}
}

func TestNew_WithOptions(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
		WithAccessTokenTTL(30*time.Minute),
		WithRefreshTokenTTL(14*24*time.Hour),
		WithTablePrefix("test_"),
		WithAPIKeyPrefix("sk_test"),
		WithAPIKeyLength(24),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	cfg := auth.Config()
	if cfg.AccessTokenTTL != 30*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, 30*time.Minute)
	}
	if cfg.RefreshTokenTTL != 14*24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want %v", cfg.RefreshTokenTTL, 14*24*time.Hour)
	}
	if cfg.TablePrefix != "test_" {
		t.Errorf("TablePrefix = %q, want %q", cfg.TablePrefix, "test_")
	}
	if cfg.APIKeyPrefix != "sk_test" {
		t.Errorf("APIKeyPrefix = %q, want %q", cfg.APIKeyPrefix, "sk_test")
	}
	if cfg.APIKeyLength != 24 {
		t.Errorf("APIKeyLength = %d, want %d", cfg.APIKeyLength, 24)
	}
}

func TestNew_WithAutoMigrate(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
		WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()
}

func TestAuth_Config(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	cfg := auth.Config()
	if cfg == nil {
		t.Fatal("Config() should not return nil")
	}
	if cfg.Secret != "this-is-a-32-character-secret!!!" {
		t.Error("Config() should return the configured secret")
	}
}

func TestAuth_Store(t *testing.T) {
	memStore := memory.New()
	defer memStore.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(memStore),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	if auth.Store() != memStore {
		t.Error("Store() should return the configured store")
	}
}

func TestAuth_IsRBACEnabled(t *testing.T) {
	store := memory.New()
	defer store.Close()

	// Without RBAC
	auth1, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth1.Close()

	if auth1.IsRBACEnabled() {
		t.Error("IsRBACEnabled() should return false without RBAC config")
	}

	// With RBAC
	auth2, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
		WithRBACFromBytes([]byte("version: 1")),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth2.Close()

	if !auth2.IsRBACEnabled() {
		t.Error("IsRBACEnabled() should return true with RBAC config")
	}
}

func TestAuth_Ping(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	if err := auth.Ping(context.Background()); err != nil {
		t.Errorf("Ping() error = %v", err)
	}
}

func TestAuth_Close(t *testing.T) {
	store := memory.New()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// First close should succeed
	if err := auth.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Second close should be idempotent
	if err := auth.Close(); err != nil {
		t.Errorf("Close() second call error = %v", err)
	}
}

func TestAuth_ClaimsInterface(t *testing.T) {
	// Verify TestClaims satisfies Claims interface
	var _ Claims = &TestClaims{}

	claims := &TestClaims{
		StandardClaims: StandardClaims{
			UserID:    "user123",
			JTI:       "jti456",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Role: "admin",
	}

	std := claims.GetStandardClaims()
	if std.UserID != "user123" {
		t.Errorf("UserID = %q, want %q", std.UserID, "user123")
	}
}

// =============================================================================
// Token Service Tests
// =============================================================================

func TestAuth_GenerateTokenPair(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()
	pair, err := auth.GenerateTokenPair(ctx, "user123", map[string]any{"role": "admin"})
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if pair.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}
	if pair.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", pair.TokenType, "Bearer")
	}
	if pair.ExpiresIn <= 0 {
		t.Error("ExpiresIn should be positive")
	}
}

func TestAuth_ValidateAccessToken(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Generate a token
	pair, err := auth.GenerateTokenPair(ctx, "user123", nil)
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	// Validate it
	claims, err := auth.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	if claims.UserID != "user123" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user123")
	}
}

func TestAuth_ValidateAccessToken_Invalid(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()
	_, err = auth.ValidateAccessToken(ctx, "invalid-token")
	if err == nil {
		t.Error("ValidateAccessToken() should return error for invalid token")
	}
}

func TestAuth_RefreshTokens(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Generate initial tokens
	pair, err := auth.GenerateTokenPair(ctx, "user123", nil)
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	// Refresh tokens
	newPair, err := auth.RefreshTokens(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens() error = %v", err)
	}

	if newPair.AccessToken == "" {
		t.Error("New AccessToken should not be empty")
	}
	if newPair.RefreshToken == "" {
		t.Error("New RefreshToken should not be empty")
	}
	if newPair.AccessToken == pair.AccessToken {
		t.Error("New AccessToken should be different from old one")
	}
}

func TestAuth_RevokeAccessToken(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Generate a token
	pair, err := auth.GenerateTokenPair(ctx, "user123", nil)
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	// Revoke it
	if err := auth.RevokeAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("RevokeAccessToken() error = %v", err)
	}

	// Validation should fail with blacklist error
	_, err = auth.ValidateAccessToken(ctx, pair.AccessToken)
	if err == nil {
		t.Error("ValidateAccessToken() should return error for revoked token")
	}
}

func TestAuth_RevokeAllUserTokens(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Generate tokens
	pair, err := auth.GenerateTokenPair(ctx, "user123", nil)
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	// Revoke all user tokens
	if err := auth.RevokeAllUserTokens(ctx, "user123"); err != nil {
		t.Fatalf("RevokeAllUserTokens() error = %v", err)
	}

	// Refresh token should be invalid
	_, err = auth.RefreshTokens(ctx, pair.RefreshToken)
	if err == nil {
		t.Error("RefreshTokens() should fail after RevokeAllUserTokens()")
	}
}

// =============================================================================
// API Key Service Tests
// =============================================================================

func TestAuth_CreateAPIKey(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()
	result, err := auth.CreateAPIKey(ctx, "user123", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	if result.RawKey == "" {
		t.Error("RawKey should not be empty")
	}
	if result.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestAuth_ValidateAPIKey(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Create a key
	createResult, err := auth.CreateAPIKey(ctx, "user123", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	// Validate it
	validateResult, err := auth.ValidateAPIKey(ctx, createResult.RawKey)
	if err != nil {
		t.Fatalf("ValidateAPIKey() error = %v", err)
	}

	if validateResult.UserID != "user123" {
		t.Errorf("UserID = %q, want %q", validateResult.UserID, "user123")
	}
}

func TestAuth_ValidateAPIKey_Invalid(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()
	_, err = auth.ValidateAPIKey(ctx, "invalid_key")
	if err == nil {
		t.Error("ValidateAPIKey() should return error for invalid key")
	}
}

func TestAuth_RevokeAPIKey(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Create a key
	createResult, err := auth.CreateAPIKey(ctx, "user123", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	// Revoke it
	if err := auth.RevokeAPIKey(ctx, createResult.ID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	// Validation should fail with revoked error
	_, err = auth.ValidateAPIKey(ctx, createResult.RawKey)
	if err == nil {
		t.Error("ValidateAPIKey() should return error for revoked key")
	}
}

func TestAuth_ListAPIKeys(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Create keys
	for i := 0; i < 3; i++ {
		_, err := auth.CreateAPIKey(ctx, "user123", nil)
		if err != nil {
			t.Fatalf("CreateAPIKey() error = %v", err)
		}
	}

	// List keys
	keys, err := auth.ListAPIKeys(ctx, "user123")
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("len(keys) = %d, want %d", len(keys), 3)
	}
}

// =============================================================================
// RBAC Tests (Disabled Mode)
// =============================================================================

func TestAuth_RBAC_NotEnabled(t *testing.T) {
	store := memory.New()
	defer store.Close()

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// All RBAC methods should return ErrRBACNotEnabled
	if err := auth.AssignRole(ctx, "user1", "admin"); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("AssignRole() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if err := auth.AddPermissions(ctx, "user1", []string{"read"}); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("AddPermissions() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if err := auth.RemovePermissions(ctx, "user1", []string{"read"}); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("RemovePermissions() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if err := auth.SetPermissions(ctx, "user1", []string{"read"}); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("SetPermissions() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if err := auth.ResetToRole(ctx, "user1"); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("ResetToRole() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if _, err := auth.GetUserPermissions(ctx, "user1"); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("GetUserPermissions() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if _, err := auth.HasPermission(ctx, "user1", "read"); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("HasPermission() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if _, err := auth.HasAllPermissions(ctx, "user1", []string{"read"}); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("HasAllPermissions() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if _, err := auth.HasAnyPermission(ctx, "user1", []string{"read"}); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("HasAnyPermission() error = %v, want %v", err, ErrRBACNotEnabled)
	}
	if err := auth.RequirePermission(ctx, "user1", "read"); !errors.Is(err, ErrRBACNotEnabled) {
		t.Errorf("RequirePermission() error = %v, want %v", err, ErrRBACNotEnabled)
	}

	// These should return nil/empty when RBAC not enabled
	if roles := auth.GetAllRoles(); roles != nil {
		t.Errorf("GetAllRoles() = %v, want nil", roles)
	}
	if groups := auth.GetAllPermissionGroups(); groups != nil {
		t.Errorf("GetAllPermissionGroups() = %v, want nil", groups)
	}
}

// =============================================================================
// RBAC Tests (Enabled Mode)
// =============================================================================

func TestAuth_RBAC_Enabled(t *testing.T) {
	store := memory.New()
	defer store.Close()

	rbacConfig := []byte(`
version: 1
permission_groups:
  - name: "Documents"
    permissions:
      - key: "documents:read"
        name: "Read Documents"
      - key: "documents:write"
        name: "Write Documents"
role_templates:
  - key: "viewer"
    name: "Viewer"
    permissions:
      - "documents:read"
  - key: "editor"
    name: "Editor"
    permissions:
      - "documents:read"
      - "documents:write"
`)

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
		WithRBACFromBytes(rbacConfig),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Assign role
	if err := auth.AssignRole(ctx, "user1", "editor"); err != nil {
		t.Fatalf("AssignRole() error = %v", err)
	}

	// Check permissions
	has, err := auth.HasPermission(ctx, "user1", "documents:read")
	if err != nil {
		t.Fatalf("HasPermission() error = %v", err)
	}
	if !has {
		t.Error("User should have documents:read permission")
	}

	has, err = auth.HasPermission(ctx, "user1", "documents:write")
	if err != nil {
		t.Fatalf("HasPermission() error = %v", err)
	}
	if !has {
		t.Error("User should have documents:write permission")
	}

	// Get roles
	roles := auth.GetAllRoles()
	if len(roles) != 2 {
		t.Errorf("len(roles) = %d, want %d", len(roles), 2)
	}

	// Get permission groups
	groups := auth.GetAllPermissionGroups()
	if len(groups) != 1 {
		t.Errorf("len(groups) = %d, want %d", len(groups), 1)
	}
}

func TestAuth_RBAC_AddRemovePermissions(t *testing.T) {
	store := memory.New()
	defer store.Close()

	rbacConfig := []byte(`
version: 1
permission_groups:
  - name: "Documents"
    permissions:
      - key: "documents:read"
        name: "Read Documents"
      - key: "documents:write"
        name: "Write Documents"
      - key: "documents:delete"
        name: "Delete Documents"
role_templates:
  - key: "viewer"
    name: "Viewer"
    permissions:
      - "documents:read"
`)

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
		WithRBACFromBytes(rbacConfig),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Assign viewer role
	if err := auth.AssignRole(ctx, "user1", "viewer"); err != nil {
		t.Fatalf("AssignRole() error = %v", err)
	}

	// Add write permission
	if err := auth.AddPermissions(ctx, "user1", []string{"documents:write"}); err != nil {
		t.Fatalf("AddPermissions() error = %v", err)
	}

	// Check has both permissions
	has, _ := auth.HasAllPermissions(ctx, "user1", []string{"documents:read", "documents:write"})
	if !has {
		t.Error("User should have both read and write permissions")
	}

	// Remove write permission
	if err := auth.RemovePermissions(ctx, "user1", []string{"documents:write"}); err != nil {
		t.Fatalf("RemovePermissions() error = %v", err)
	}

	// Check only has read
	has, _ = auth.HasPermission(ctx, "user1", "documents:read")
	if !has {
		t.Error("User should still have read permission")
	}
	has, _ = auth.HasPermission(ctx, "user1", "documents:write")
	if has {
		t.Error("User should not have write permission after removal")
	}
}
