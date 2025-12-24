//go:build integration

package sql

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	// Database drivers
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/aloks98/goauth/store"
)

// Test connection strings - can be overridden via environment variables
// Default ports are offset to avoid conflicts (15432 for Postgres, 13306 for MySQL)
var (
	postgresDSN = getEnv("POSTGRES_DSN", "postgres://goauth:goauth@localhost:15432/goauth_test?sslmode=disable")
	mysqlDSN    = getEnv("MYSQL_DSN", "goauth:goauth@tcp(localhost:13306)/goauth_test?parseTime=true")
)

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// TestPostgres_Integration runs integration tests against PostgreSQL
func TestPostgres_Integration(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Dialect:      PostgreSQL,
		DSN:          postgresDSN,
		TablePrefix:  "test_",
		MaxOpenConns: 5,
	}

	s, err := New(cfg)
	if err != nil {
		t.Skipf("Skipping PostgreSQL tests: %v", err)
	}
	defer s.Close()

	// Run migration
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	// Run all store tests
	runStoreTests(t, s)
}

// TestMySQL_Integration runs integration tests against MySQL
func TestMySQL_Integration(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Dialect:      MySQL,
		DSN:          mysqlDSN,
		TablePrefix:  "test_",
		MaxOpenConns: 5,
	}

	s, err := New(cfg)
	if err != nil {
		t.Skipf("Skipping MySQL tests: %v", err)
	}
	defer s.Close()

	// Run migration
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	// Run all store tests
	runStoreTests(t, s)
}

func runStoreTests(t *testing.T, s store.Store) {
	t.Run("Ping", func(t *testing.T) {
		testStorePing(t, s)
	})

	t.Run("RefreshToken", func(t *testing.T) {
		testStoreRefreshToken(t, s)
	})

	t.Run("RevokeTokenFamily", func(t *testing.T) {
		testStoreRevokeTokenFamily(t, s)
	})

	t.Run("RevokeAllUserTokens", func(t *testing.T) {
		testStoreRevokeAllUserTokens(t, s)
	})

	t.Run("Blacklist", func(t *testing.T) {
		testStoreBlacklist(t, s)
	})

	t.Run("UserPermissions", func(t *testing.T) {
		testStoreUserPermissions(t, s)
	})

	t.Run("RoleTemplates", func(t *testing.T) {
		testStoreRoleTemplates(t, s)
	})

	t.Run("APIKey", func(t *testing.T) {
		testStoreAPIKey(t, s)
	})

	t.Run("Concurrent", func(t *testing.T) {
		testStoreConcurrent(t, s)
	})
}

func testStorePing(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.Ping(ctx); err != nil {
		t.Errorf("Ping() error = %v", err)
	}
}

func testStoreRefreshToken(t *testing.T, s store.Store) {
	ctx := context.Background()

	token := &store.RefreshToken{
		ID:        "rt-" + time.Now().Format("20060102150405.000"),
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
	got, err := s.GetRefreshToken(ctx, token.ID)
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
	if err := s.RevokeRefreshToken(ctx, token.ID, "rt-replacement"); err != nil {
		t.Fatalf("RevokeRefreshToken() error = %v", err)
	}

	got, _ = s.GetRefreshToken(ctx, token.ID)
	if got == nil || got.RevokedAt == nil {
		t.Error("Token should be revoked")
	}
}

func testStoreRevokeTokenFamily(t *testing.T, s store.Store) {
	ctx := context.Background()
	familyID := "family-" + time.Now().Format("20060102150405.000")

	// Create tokens in same family
	for i := 0; i < 3; i++ {
		token := &store.RefreshToken{
			ID:        familyID + "-" + string(rune('a'+i)),
			UserID:    "user-1",
			FamilyID:  familyID,
			TokenHash: "hash",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := s.SaveRefreshToken(ctx, token); err != nil {
			t.Fatalf("SaveRefreshToken() error = %v", err)
		}
	}

	// Revoke family
	if err := s.RevokeTokenFamily(ctx, familyID); err != nil {
		t.Fatalf("RevokeTokenFamily() error = %v", err)
	}

	// All should be revoked
	for _, suffix := range []string{"-a", "-b", "-c"} {
		got, _ := s.GetRefreshToken(ctx, familyID+suffix)
		if got != nil && got.RevokedAt == nil {
			t.Errorf("Token %s should be revoked", familyID+suffix)
		}
	}
}

func testStoreRevokeAllUserTokens(t *testing.T, s store.Store) {
	ctx := context.Background()
	userID := "user-revoke-all-" + time.Now().Format("20060102150405.000")

	// Create tokens
	for i := 0; i < 3; i++ {
		token := &store.RefreshToken{
			ID:        userID + "-token-" + string(rune('a'+i)),
			UserID:    userID,
			FamilyID:  "family-" + string(rune('a'+i)),
			TokenHash: "hash",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := s.SaveRefreshToken(ctx, token); err != nil {
			t.Fatalf("SaveRefreshToken() error = %v", err)
		}
	}

	// Revoke all
	if err := s.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
		t.Fatalf("RevokeAllUserRefreshTokens() error = %v", err)
	}

	// All should be revoked
	for _, suffix := range []string{"-token-a", "-token-b", "-token-c"} {
		got, _ := s.GetRefreshToken(ctx, userID+suffix)
		if got != nil && got.RevokedAt == nil {
			t.Errorf("Token %s should be revoked", userID+suffix)
		}
	}
}

func testStoreBlacklist(t *testing.T, s store.Store) {
	ctx := context.Background()
	jti := "jti-" + time.Now().Format("20060102150405.000")

	// Add to blacklist
	if err := s.AddToBlacklist(ctx, jti, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("AddToBlacklist() error = %v", err)
	}

	// Check blacklisted
	ok, err := s.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !ok {
		t.Error("JTI should be blacklisted")
	}

	// Check not blacklisted
	ok, _ = s.IsBlacklisted(ctx, "nonexistent-jti")
	if ok {
		t.Error("Nonexistent JTI should not be blacklisted")
	}
}

func testStoreUserPermissions(t *testing.T, s store.Store) {
	ctx := context.Background()
	userID := "user-perms-" + time.Now().Format("20060102150405.000")

	perms := &store.UserPermissions{
		UserID:            userID,
		RoleLabel:         "admin",
		BaseRole:          "admin",
		Permissions:       []string{"read", "write", "delete"},
		PermissionVersion: 1,
		UpdatedAt:         time.Now(),
	}

	// Save
	if err := s.SaveUserPermissions(ctx, perms); err != nil {
		t.Fatalf("SaveUserPermissions() error = %v", err)
	}

	// Get
	got, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserPermissions() error = %v", err)
	}
	if got.RoleLabel != "admin" {
		t.Errorf("RoleLabel = %q, want %q", got.RoleLabel, "admin")
	}
	if len(got.Permissions) != 3 {
		t.Errorf("len(Permissions) = %d, want 3", len(got.Permissions))
	}

	// Update
	perms.Permissions = []string{"read"}
	perms.PermissionVersion = 2
	if err := s.SaveUserPermissions(ctx, perms); err != nil {
		t.Fatalf("SaveUserPermissions() update error = %v", err)
	}

	got, _ = s.GetUserPermissions(ctx, userID)
	if got.PermissionVersion != 2 {
		t.Errorf("PermissionVersion = %d, want 2", got.PermissionVersion)
	}

	// Delete
	if err := s.DeleteUserPermissions(ctx, userID); err != nil {
		t.Fatalf("DeleteUserPermissions() error = %v", err)
	}

	got, _ = s.GetUserPermissions(ctx, userID)
	if got != nil {
		t.Error("Permissions should be deleted")
	}
}

func testStoreRoleTemplates(t *testing.T, s store.Store) {
	ctx := context.Background()
	roleKey := "role-" + time.Now().Format("20060102150405.000")

	template := &store.StoredRoleTemplate{
		Key:            roleKey,
		Name:           "Test Role",
		Description:    "A test role",
		Permissions:    []string{"read", "write"},
		PermissionHash: "hash123",
		Version:        1,
		UpdatedAt:      time.Now(),
	}

	// Save
	if err := s.SaveRoleTemplate(ctx, template); err != nil {
		t.Fatalf("SaveRoleTemplate() error = %v", err)
	}

	// Get all
	templates, err := s.GetRoleTemplates(ctx)
	if err != nil {
		t.Fatalf("GetRoleTemplates() error = %v", err)
	}

	found := false
	for _, tmpl := range templates {
		if tmpl.Key == roleKey {
			found = true
			// Note: Name and Description are not stored in the database schema
			if len(tmpl.Permissions) != 2 {
				t.Errorf("len(Permissions) = %d, want 2", len(tmpl.Permissions))
			}
			if tmpl.PermissionHash != "hash123" {
				t.Errorf("PermissionHash = %q, want %q", tmpl.PermissionHash, "hash123")
			}
		}
	}
	if !found {
		t.Error("Role template not found in GetRoleTemplates()")
	}
}

func testStoreAPIKey(t *testing.T, s store.Store) {
	ctx := context.Background()
	keyID := "key-" + time.Now().Format("20060102150405.000")

	key := &store.APIKey{
		ID:        keyID,
		UserID:    "user-1",
		Name:      "Test Key",
		Prefix:    "sk_test",
		KeyHash:   "hash-" + keyID,
		Hint:      "abcd",
		Scopes:    []string{"read", "write"},
		CreatedAt: time.Now(),
	}

	// Save
	if err := s.SaveAPIKey(ctx, key); err != nil {
		t.Fatalf("SaveAPIKey() error = %v", err)
	}

	// Get by hash
	got, err := s.GetAPIKeyByHash(ctx, "sk_test", "hash-"+keyID)
	if err != nil {
		t.Fatalf("GetAPIKeyByHash() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAPIKeyByHash() returned nil")
	}
	if got.Name != "Test Key" {
		t.Errorf("Name = %q, want %q", got.Name, "Test Key")
	}

	// Get by user
	keys, err := s.GetAPIKeysByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetAPIKeysByUser() error = %v", err)
	}

	found := false
	for _, k := range keys {
		if k.ID == keyID {
			found = true
		}
	}
	if !found {
		t.Error("API key not found in GetAPIKeysByUser()")
	}

	// Revoke
	if err := s.RevokeAPIKey(ctx, keyID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	got, _ = s.GetAPIKeyByHash(ctx, "sk_test", "hash-"+keyID)
	if got != nil && got.RevokedAt == nil {
		t.Error("API key should be revoked")
	}
}

func testStoreConcurrent(t *testing.T, s store.Store) {
	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrent token operations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			token := &store.RefreshToken{
				ID:        "concurrent-" + time.Now().Format("20060102150405.000000") + "-" + string(rune('0'+id)),
				UserID:    "user-concurrent",
				FamilyID:  "family-concurrent",
				TokenHash: "hash",
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			}

			if err := s.SaveRefreshToken(ctx, token); err != nil {
				t.Errorf("Concurrent SaveRefreshToken() error = %v", err)
			}

			if _, err := s.GetRefreshToken(ctx, token.ID); err != nil {
				t.Errorf("Concurrent GetRefreshToken() error = %v", err)
			}
		}(i)
	}

	wg.Wait()
}
