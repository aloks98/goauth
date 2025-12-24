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

func TestStore_RevokeAllUserRefreshTokens(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Create tokens for two users
	tokens := []*store.RefreshToken{
		{ID: "t1", UserID: "user-1", FamilyID: "f1", ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "t2", UserID: "user-1", FamilyID: "f2", ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "t3", UserID: "user-2", FamilyID: "f3", ExpiresAt: time.Now().Add(time.Hour)},
	}
	for _, tok := range tokens {
		s.SaveRefreshToken(ctx, tok)
	}

	// Revoke all for user-1
	if err := s.RevokeAllUserRefreshTokens(ctx, "user-1"); err != nil {
		t.Fatalf("RevokeAllUserRefreshTokens() error = %v", err)
	}

	// user-1 tokens should be revoked
	for _, id := range []string{"t1", "t2"} {
		got, _ := s.GetRefreshToken(ctx, id)
		if got.RevokedAt == nil {
			t.Errorf("Token %s should be revoked", id)
		}
	}

	// user-2 token should NOT be revoked
	got, _ := s.GetRefreshToken(ctx, "t3")
	if got.RevokedAt != nil {
		t.Error("Token t3 should not be revoked")
	}
}

func TestStore_DeleteExpiredRefreshTokens(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Create expired and valid tokens
	tokens := []*store.RefreshToken{
		{ID: "expired1", UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour)},
		{ID: "expired2", UserID: "u1", ExpiresAt: time.Now().Add(-time.Minute)},
		{ID: "valid", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)},
	}
	for _, tok := range tokens {
		s.SaveRefreshToken(ctx, tok)
	}

	// Delete expired
	deleted, err := s.DeleteExpiredRefreshTokens(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredRefreshTokens() error = %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	// Expired should be gone
	got, _ := s.GetRefreshToken(ctx, "expired1")
	if got != nil {
		t.Error("expired1 should be deleted")
	}

	// Valid should remain
	got, _ = s.GetRefreshToken(ctx, "valid")
	if got == nil {
		t.Error("valid token should still exist")
	}
}

func TestStore_DeleteExpiredBlacklistEntries(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Add expired and valid blacklist entries
	s.AddToBlacklist(ctx, "expired1", time.Now().Add(-time.Hour).Unix())
	s.AddToBlacklist(ctx, "expired2", time.Now().Add(-time.Minute).Unix())
	s.AddToBlacklist(ctx, "valid", time.Now().Add(time.Hour).Unix())

	// Delete expired
	deleted, err := s.DeleteExpiredBlacklistEntries(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredBlacklistEntries() error = %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	// Expired should be gone
	ok, _ := s.IsBlacklisted(ctx, "expired1")
	if ok {
		t.Error("expired1 should be removed from blacklist")
	}

	// Valid should remain
	ok, _ = s.IsBlacklisted(ctx, "valid")
	if !ok {
		t.Error("valid should still be blacklisted")
	}
}

func TestStore_RoleTemplates(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Save role templates
	templates := []*store.StoredRoleTemplate{
		{Key: "admin", Name: "Admin", Permissions: []string{"*"}, PermissionHash: "hash1"},
		{Key: "user", Name: "User", Permissions: []string{"read"}, PermissionHash: "hash2"},
	}
	for _, tmpl := range templates {
		if err := s.SaveRoleTemplate(ctx, tmpl); err != nil {
			t.Fatalf("SaveRoleTemplate() error = %v", err)
		}
	}

	// Get role templates
	got, err := s.GetRoleTemplates(ctx)
	if err != nil {
		t.Fatalf("GetRoleTemplates() error = %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len(got) = %d, want 2", len(got))
	}
}

func TestStore_UpdateUsersWithRole(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Create users with roles
	users := []*store.UserPermissions{
		{UserID: "u1", RoleLabel: "admin", BaseRole: "admin", Permissions: []string{"old"}, PermissionVersion: 1},
		{UserID: "u2", RoleLabel: "admin", BaseRole: "admin", Permissions: []string{"old"}, PermissionVersion: 1},
		{UserID: "u3", RoleLabel: "user", BaseRole: "user", Permissions: []string{"read"}, PermissionVersion: 1},
		{UserID: "u4", RoleLabel: "custom", BaseRole: "admin", Permissions: []string{"custom"}, PermissionVersion: 1},
	}
	for _, u := range users {
		s.SaveUserPermissions(ctx, u)
	}

	// Update users with admin role
	newPerms := []string{"read", "write", "admin"}
	affected, err := s.UpdateUsersWithRole(ctx, "admin", newPerms, 2)
	if err != nil {
		t.Fatalf("UpdateUsersWithRole() error = %v", err)
	}
	if affected != 2 {
		t.Errorf("affected = %d, want 2", affected)
	}

	// u1 and u2 should have new permissions
	for _, id := range []string{"u1", "u2"} {
		got, _ := s.GetUserPermissions(ctx, id)
		if len(got.Permissions) != 3 {
			t.Errorf("user %s permissions = %v, want 3 permissions", id, got.Permissions)
		}
		if got.PermissionVersion != 2 {
			t.Errorf("user %s version = %d, want 2", id, got.PermissionVersion)
		}
	}

	// u3 should be unchanged (different role)
	got, _ := s.GetUserPermissions(ctx, "u3")
	if len(got.Permissions) != 1 {
		t.Errorf("u3 permissions should be unchanged")
	}

	// u4 should be unchanged (custom role label)
	got, _ = s.GetUserPermissions(ctx, "u4")
	if len(got.Permissions) != 1 {
		t.Errorf("u4 permissions should be unchanged (custom)")
	}
}

func TestStore_DeleteExpiredAPIKeys(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	now := time.Now()
	expired := now.Add(-time.Hour)
	valid := now.Add(time.Hour)

	// Create expired and valid API keys
	keys := []*store.APIKey{
		{ID: "k1", UserID: "u1", Prefix: "sk", KeyHash: "h1", ExpiresAt: &expired},
		{ID: "k2", UserID: "u1", Prefix: "sk", KeyHash: "h2", ExpiresAt: &expired},
		{ID: "k3", UserID: "u1", Prefix: "sk", KeyHash: "h3", ExpiresAt: &valid},
		{ID: "k4", UserID: "u1", Prefix: "sk", KeyHash: "h4", ExpiresAt: nil}, // No expiry
	}
	for _, k := range keys {
		s.SaveAPIKey(ctx, k)
	}

	// Delete expired
	deleted, err := s.DeleteExpiredAPIKeys(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredAPIKeys() error = %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	// Check remaining keys
	remaining, _ := s.GetAPIKeysByUser(ctx, "u1")
	if len(remaining) != 2 {
		t.Errorf("remaining keys = %d, want 2", len(remaining))
	}
}

func TestStore_GetAPIKeyByHash_NotFound(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Try to get non-existent key
	got, err := s.GetAPIKeyByHash(ctx, "sk", "nonexistent")
	if err != nil {
		t.Fatalf("GetAPIKeyByHash() error = %v", err)
	}
	if got != nil {
		t.Error("expected nil for non-existent key")
	}
}

func TestStore_GetRefreshToken_NotFound(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	got, err := s.GetRefreshToken(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}
	if got != nil {
		t.Error("expected nil for non-existent token")
	}
}

func TestStore_Concurrent(t *testing.T) {
	s := New()
	defer s.Close()
	ctx := context.Background()

	// Test concurrent access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			token := &store.RefreshToken{
				ID:        "token-" + string(rune('0'+id)),
				UserID:    "user-1",
				FamilyID:  "family-1",
				ExpiresAt: time.Now().Add(time.Hour),
			}
			s.SaveRefreshToken(ctx, token)
			s.GetRefreshToken(ctx, token.ID)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Verify interface implementation
var _ store.Store = (*Store)(nil)
