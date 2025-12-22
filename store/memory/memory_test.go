package memory

import (
	"context"
	"testing"
	"time"

	"github.com/aloks98/goauth/store"
)

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
	defer s.Close()
}

func TestStore_PingAndClose(t *testing.T) {
	s := New()

	if err := s.Ping(context.Background()); err != nil {
		t.Errorf("Ping() error = %v", err)
	}

	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestStore_Migrate(t *testing.T) {
	s := New()
	defer s.Close()

	if err := s.Migrate(context.Background()); err != nil {
		t.Errorf("Migrate() error = %v", err)
	}
}

func TestStore_RefreshToken(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	token := &store.RefreshToken{
		ID:        "token-1",
		UserID:    "user-1",
		FamilyID:  "family-1",
		TokenHash: "hash-1",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Save
	if err := s.SaveRefreshToken(ctx, token); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Get
	got, err := s.GetRefreshToken(ctx, "token-1")
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetRefreshToken() returned nil")
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-1")
	}

	// Revoke
	if err := s.RevokeRefreshToken(ctx, "token-1", "token-2"); err != nil {
		t.Fatalf("RevokeRefreshToken() error = %v", err)
	}

	got, _ = s.GetRefreshToken(ctx, "token-1")
	if got.RevokedAt == nil {
		t.Error("Token should be revoked")
	}
}

func TestStore_RevokeTokenFamily(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Create tokens in same family
	for i := 0; i < 3; i++ {
		token := &store.RefreshToken{
			ID:        "token-" + string(rune('a'+i)),
			UserID:    "user-1",
			FamilyID:  "family-1",
			ExpiresAt: time.Now().Add(time.Hour),
		}
		s.SaveRefreshToken(ctx, token)
	}

	// Revoke family
	if err := s.RevokeTokenFamily(ctx, "family-1"); err != nil {
		t.Fatalf("RevokeTokenFamily() error = %v", err)
	}

	// All should be revoked
	for _, id := range []string{"token-a", "token-b", "token-c"} {
		got, _ := s.GetRefreshToken(ctx, id)
		if got != nil && got.RevokedAt == nil {
			t.Errorf("Token %s should be revoked", id)
		}
	}
}

func TestStore_Blacklist(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Add to blacklist
	if err := s.AddToBlacklist(ctx, "jti-1", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("AddToBlacklist() error = %v", err)
	}

	// Check blacklisted
	ok, err := s.IsBlacklisted(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !ok {
		t.Error("jti-1 should be blacklisted")
	}

	// Check not blacklisted
	ok, _ = s.IsBlacklisted(ctx, "jti-2")
	if ok {
		t.Error("jti-2 should not be blacklisted")
	}
}

func TestStore_UserPermissions(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	perms := &store.UserPermissions{
		UserID:            "user-1",
		RoleLabel:         "admin",
		Permissions:       []string{"read", "write"},
		PermissionVersion: 1,
	}

	// Save
	if err := s.SaveUserPermissions(ctx, perms); err != nil {
		t.Fatalf("SaveUserPermissions() error = %v", err)
	}

	// Get
	got, err := s.GetUserPermissions(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetUserPermissions() error = %v", err)
	}
	if got.RoleLabel != "admin" {
		t.Errorf("RoleLabel = %q, want %q", got.RoleLabel, "admin")
	}

	// Delete
	if err := s.DeleteUserPermissions(ctx, "user-1"); err != nil {
		t.Fatalf("DeleteUserPermissions() error = %v", err)
	}

	got, _ = s.GetUserPermissions(ctx, "user-1")
	if got != nil {
		t.Error("Permissions should be deleted")
	}
}

func TestStore_APIKey(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	key := &store.APIKey{
		ID:      "key-1",
		UserID:  "user-1",
		Name:    "Test Key",
		Prefix:  "sk_test",
		KeyHash: "hash123",
	}

	// Save
	if err := s.SaveAPIKey(ctx, key); err != nil {
		t.Fatalf("SaveAPIKey() error = %v", err)
	}

	// Get by hash
	got, err := s.GetAPIKeyByHash(ctx, "sk_test", "hash123")
	if err != nil {
		t.Fatalf("GetAPIKeyByHash() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAPIKeyByHash() returned nil")
	}

	// Get by user
	keys, err := s.GetAPIKeysByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetAPIKeysByUser() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}

	// Revoke
	if err := s.RevokeAPIKey(ctx, "key-1"); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
}

// Verify interface implementation
var _ store.Store = (*Store)(nil)
