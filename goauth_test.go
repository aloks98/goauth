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
