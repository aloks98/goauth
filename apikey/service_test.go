package apikey

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aloks98/goauth/store/memory"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	s := memory.New()
	cfg := &Config{
		Prefix:     "sk_test",
		KeyLength:  32,
		HintLength: 4,
	}
	return NewService(cfg, s)
}

func TestNewService(t *testing.T) {
	s := memory.New()

	// Test with nil config
	svc := NewService(nil, s)
	if svc.config.Prefix != "sk" {
		t.Errorf("expected default prefix 'sk', got %q", svc.config.Prefix)
	}
	if svc.config.KeyLength != 32 {
		t.Errorf("expected key length 32, got %d", svc.config.KeyLength)
	}

	// Test with custom config
	cfg := &Config{
		Prefix:     "api",
		KeyLength:  64,
		HintLength: 6,
	}
	svc = NewService(cfg, s)
	if svc.config.Prefix != "api" {
		t.Errorf("expected prefix 'api', got %q", svc.config.Prefix)
	}
}

func TestCreateKey(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	result, err := svc.CreateKey(ctx, "user-123", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID == "" {
		t.Error("expected ID to be non-empty")
	}
	if result.RawKey == "" {
		t.Error("expected RawKey to be non-empty")
	}
	if !strings.HasPrefix(result.RawKey, "sk_test.") {
		t.Errorf("expected key to start with 'sk_test.', got %q", result.RawKey)
	}
	if result.Prefix != "sk_test" {
		t.Errorf("expected prefix 'sk_test', got %q", result.Prefix)
	}
	if len(result.Hint) != 4 {
		t.Errorf("expected hint length 4, got %d", len(result.Hint))
	}
}

func TestCreateKeyWithOptions(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	expiresAt := time.Now().Add(24 * time.Hour)
	opts := &CreateKeyOptions{
		Name:      "My API Key",
		Scopes:    []string{"read:users", "write:posts"},
		ExpiresAt: &expiresAt,
	}

	result, err := svc.CreateKey(ctx, "user-123", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Name != "My API Key" {
		t.Errorf("expected name 'My API Key', got %q", result.Name)
	}
	if result.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}
}

func TestCreateKeyWithTTL(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	opts := &CreateKeyOptions{
		TTL: 1 * time.Hour,
	}

	result, err := svc.CreateKey(ctx, "user-123", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set from TTL")
	}
	// Check it's approximately 1 hour from now
	diff := time.Until(*result.ExpiresAt)
	if diff < 59*time.Minute || diff > 61*time.Minute {
		t.Errorf("expected expiration ~1 hour from now, got %v", diff)
	}
}

func TestValidateKey(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create a key
	createResult, err := svc.CreateKey(ctx, "user-123", nil)
	if err != nil {
		t.Fatalf("unexpected error creating key: %v", err)
	}

	// Validate it
	validateResult, err := svc.ValidateKey(ctx, createResult.RawKey)
	if err != nil {
		t.Fatalf("unexpected error validating key: %v", err)
	}

	if validateResult.UserID != "user-123" {
		t.Errorf("expected user ID 'user-123', got %q", validateResult.UserID)
	}
	if validateResult.Key == nil {
		t.Error("expected Key to be non-nil")
	}
}

func TestValidateKey_Invalid(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	tests := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"no separator", "invalidkey"},
		{"invalid base64", "sk_test_!!!invalid!!!"},
		{"nonexistent", "sk_test_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateKey(ctx, tt.key)
			if err == nil {
				t.Error("expected error for invalid key")
			}
		})
	}
}

func TestValidateKey_Revoked(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create and revoke a key
	result, _ := svc.CreateKey(ctx, "user-123", nil)
	if err := svc.RevokeKey(ctx, result.ID); err != nil {
		t.Fatalf("unexpected error revoking key: %v", err)
	}

	// Validate should fail
	_, err := svc.ValidateKey(ctx, result.RawKey)
	if err != ErrKeyRevoked {
		t.Errorf("expected ErrKeyRevoked, got %v", err)
	}
}

func TestValidateKey_Expired(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create a key that's already expired
	pastTime := time.Now().Add(-1 * time.Hour)
	opts := &CreateKeyOptions{
		ExpiresAt: &pastTime,
	}
	result, _ := svc.CreateKey(ctx, "user-123", opts)

	// Validate should fail
	_, err := svc.ValidateKey(ctx, result.RawKey)
	if err != ErrKeyExpired {
		t.Errorf("expected ErrKeyExpired, got %v", err)
	}
}

func TestValidateKeyWithScope(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create a key with specific scopes
	opts := &CreateKeyOptions{
		Scopes: []string{"read:users", "write:posts"},
	}
	result, _ := svc.CreateKey(ctx, "user-123", opts)

	// Validate with allowed scope
	_, err := svc.ValidateKeyWithScope(ctx, result.RawKey, "read:users")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Validate with disallowed scope
	_, err = svc.ValidateKeyWithScope(ctx, result.RawKey, "delete:users")
	if err != ErrScopeNotAllowed {
		t.Errorf("expected ErrScopeNotAllowed, got %v", err)
	}
}

func TestValidateKeyWithScope_NoScopes(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create a key without scopes (allows all)
	result, _ := svc.CreateKey(ctx, "user-123", nil)

	// Should allow any scope
	_, err := svc.ValidateKeyWithScope(ctx, result.RawKey, "anything:goes")
	if err != nil {
		t.Errorf("key without scopes should allow any scope, got %v", err)
	}
}

func TestRevokeKey(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	result, _ := svc.CreateKey(ctx, "user-123", nil)

	// Revoke the key
	if err := svc.RevokeKey(ctx, result.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Key should no longer validate
	_, err := svc.ValidateKey(ctx, result.RawKey)
	if err != ErrKeyRevoked {
		t.Errorf("expected ErrKeyRevoked, got %v", err)
	}
}

func TestListKeys(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create multiple keys for the same user
	for i := 0; i < 3; i++ {
		_, err := svc.CreateKey(ctx, "user-123", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Create a key for a different user
	_, _ = svc.CreateKey(ctx, "user-456", nil)

	// List keys for user-123
	keys, err := svc.ListKeys(ctx, "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	// Verify keys don't contain raw key
	for _, key := range keys {
		if key.KeyHash == "" {
			t.Error("key should have hash")
		}
	}
}

func TestCleanupExpired(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create expired keys
	pastTime := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 3; i++ {
		opts := &CreateKeyOptions{
			ExpiresAt: &pastTime,
		}
		_, _ = svc.CreateKey(ctx, "user-123", opts)
	}

	// Create valid key
	_, _ = svc.CreateKey(ctx, "user-123", nil)

	// Cleanup
	deleted, err := svc.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if deleted != 3 {
		t.Errorf("expected 3 deleted, got %d", deleted)
	}

	// Check only valid key remains
	keys, _ := svc.ListKeys(ctx, "user-123")
	if len(keys) != 1 {
		t.Errorf("expected 1 key remaining, got %d", len(keys))
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Prefix != "sk" {
		t.Errorf("expected prefix 'sk', got %q", cfg.Prefix)
	}
	if cfg.KeyLength != 32 {
		t.Errorf("expected key length 32, got %d", cfg.KeyLength)
	}
	if cfg.HintLength != 4 {
		t.Errorf("expected hint length 4, got %d", cfg.HintLength)
	}
	if cfg.DefaultTTL != 0 {
		t.Errorf("expected default TTL 0, got %v", cfg.DefaultTTL)
	}
}

func TestKeyUniqueness(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	keys := make(map[string]bool)
	for i := 0; i < 100; i++ {
		result, err := svc.CreateKey(ctx, "user-123", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keys[result.RawKey] {
			t.Error("duplicate key generated")
		}
		keys[result.RawKey] = true
	}
}
