package rbac

import (
	"context"
	"testing"

	"github.com/aloks98/goauth/internal/testutil"
)

func newTestConfig() *Config {
	return &Config{
		Version: 1,
		PermissionGroups: []PermissionGroup{
			{
				Name: "Users",
				Permissions: []Permission{
					{Key: "users:read", Name: "Read Users"},
					{Key: "users:write", Name: "Write Users"},
					{Key: "users:delete", Name: "Delete Users"},
				},
			},
			{
				Name: "Posts",
				Permissions: []Permission{
					{Key: "posts:read", Name: "Read Posts"},
					{Key: "posts:write", Name: "Write Posts"},
				},
			},
		},
		RoleTemplates: []RoleTemplate{
			{Key: "admin", Name: "Administrator", Permissions: []string{"*"}},
			{Key: "editor", Name: "Editor", Permissions: []string{"users:read", "posts:*"}},
			{Key: "viewer", Name: "Viewer", Permissions: []string{"users:read", "posts:read"}},
		},
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	cfg := newTestConfig()
	s := testutil.SetupPostgres(t)
	svc, err := NewService(cfg, s)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	return svc
}

func TestNewService(t *testing.T) {
	cfg := newTestConfig()
	s := testutil.SetupPostgres(t)

	svc, err := NewService(cfg, s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Error("expected non-nil service")
	}
}

func TestNewService_NilConfig(t *testing.T) {
	s := testutil.SetupPostgres(t)
	_, err := NewService(nil, s)
	if err != ErrRBACNotEnabled {
		t.Errorf("expected ErrRBACNotEnabled, got %v", err)
	}
}

func TestNewService_InvalidConfig(t *testing.T) {
	cfg := &Config{
		PermissionGroups: []PermissionGroup{
			{
				Name: "Bad",
				Permissions: []Permission{
					{Key: "", Name: "Empty Key"},
				},
			},
		},
	}
	s := testutil.SetupPostgres(t)
	_, err := NewService(cfg, s)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestService_AssignRole(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Assign editor role
	if err := svc.AssignRole(ctx, "user-123", "editor"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify permissions
	perms, err := svc.GetUserPermissions(ctx, "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if perms.RoleLabel != "editor" {
		t.Errorf("expected role label 'editor', got %s", perms.RoleLabel)
	}
	if perms.BaseRole != "editor" {
		t.Errorf("expected base role 'editor', got %s", perms.BaseRole)
	}

	// Editor has users:read and posts:*
	// posts:* expands to posts:read and posts:write
	if !perms.HasPermission("users:read") {
		t.Error("expected users:read permission")
	}
	if !perms.HasPermission("posts:read") {
		t.Error("expected posts:read permission")
	}
	if !perms.HasPermission("posts:write") {
		t.Error("expected posts:write permission")
	}
	if perms.HasPermission("users:write") {
		t.Error("should not have users:write permission")
	}
}

func TestService_AssignRole_NotFound(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	err := svc.AssignRole(ctx, "user-123", "nonexistent")
	if err != ErrRoleNotFound {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestService_AssignRole_Admin(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Assign admin role (has * permission)
	if err := svc.AssignRole(ctx, "user-123", "admin"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	perms, _ := svc.GetUserPermissions(ctx, "user-123")

	// Admin should have all permissions
	if !perms.HasPermission("users:read") {
		t.Error("expected users:read permission")
	}
	if !perms.HasPermission("users:delete") {
		t.Error("expected users:delete permission")
	}
	if !perms.HasPermission("posts:write") {
		t.Error("expected posts:write permission")
	}
}

func TestService_AddPermissions(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Start with viewer role
	svc.AssignRole(ctx, "user-123", "viewer")

	// Add extra permission
	if err := svc.AddPermissions(ctx, "user-123", []string{"users:write"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	perms, _ := svc.GetUserPermissions(ctx, "user-123")

	// Should have original + new permission
	if !perms.HasPermission("users:read") {
		t.Error("expected users:read permission")
	}
	if !perms.HasPermission("users:write") {
		t.Error("expected users:write permission")
	}

	// Should be marked as custom
	if perms.RoleLabel != "custom" {
		t.Errorf("expected role label 'custom', got %s", perms.RoleLabel)
	}
	// But should still track base role
	if perms.BaseRole != "viewer" {
		t.Errorf("expected base role 'viewer', got %s", perms.BaseRole)
	}
}

func TestService_AddPermissions_NewUser(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Add permissions to user without existing permissions
	if err := svc.AddPermissions(ctx, "new-user", []string{"posts:read"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	perms, _ := svc.GetUserPermissions(ctx, "new-user")
	if !perms.HasPermission("posts:read") {
		t.Error("expected posts:read permission")
	}
	if perms.RoleLabel != "custom" {
		t.Errorf("expected role label 'custom', got %s", perms.RoleLabel)
	}
}

func TestService_RemovePermissions(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Start with admin role (all permissions)
	svc.AssignRole(ctx, "user-123", "admin")

	// Remove some permissions
	if err := svc.RemovePermissions(ctx, "user-123", []string{"users:delete", "posts:write"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	perms, _ := svc.GetUserPermissions(ctx, "user-123")

	if perms.HasPermission("users:delete") {
		t.Error("should not have users:delete permission")
	}
	if perms.HasPermission("posts:write") {
		t.Error("should not have posts:write permission")
	}
	if !perms.HasPermission("users:read") {
		t.Error("expected users:read permission")
	}

	if perms.RoleLabel != "custom" {
		t.Errorf("expected role label 'custom', got %s", perms.RoleLabel)
	}
}

func TestService_SetPermissions(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Set specific permissions
	if err := svc.SetPermissions(ctx, "user-123", []string{"users:read", "posts:read"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	perms, _ := svc.GetUserPermissions(ctx, "user-123")

	if len(perms.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(perms.Permissions))
	}
	if perms.RoleLabel != "custom" {
		t.Errorf("expected role label 'custom', got %s", perms.RoleLabel)
	}
}

func TestService_ResetToRole(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Assign viewer, customize, then reset
	svc.AssignRole(ctx, "user-123", "viewer")
	svc.AddPermissions(ctx, "user-123", []string{"users:delete"})

	perms, _ := svc.GetUserPermissions(ctx, "user-123")
	if perms.RoleLabel != "custom" {
		t.Error("expected custom role after adding permissions")
	}

	// Reset to base role
	if err := svc.ResetToRole(ctx, "user-123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	perms, _ = svc.GetUserPermissions(ctx, "user-123")
	if perms.RoleLabel != "viewer" {
		t.Errorf("expected role label 'viewer' after reset, got %s", perms.RoleLabel)
	}
	if perms.HasPermission("users:delete") {
		t.Error("should not have users:delete after reset")
	}
}

func TestService_ResetToRole_NoBaseRole(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// User with custom permissions only (no base role)
	svc.SetPermissions(ctx, "user-123", []string{"users:read"})

	err := svc.ResetToRole(ctx, "user-123")
	if err != ErrRoleNotFound {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestService_HasPermission(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	svc.AssignRole(ctx, "user-123", "viewer")

	has, err := svc.HasPermission(ctx, "user-123", "users:read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Error("expected to have users:read permission")
	}

	has, _ = svc.HasPermission(ctx, "user-123", "users:delete")
	if has {
		t.Error("should not have users:delete permission")
	}
}

func TestService_HasPermission_NoUser(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	has, err := svc.HasPermission(ctx, "nonexistent", "users:read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("nonexistent user should not have permission")
	}
}

func TestService_HasAllPermissions(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	svc.AssignRole(ctx, "user-123", "editor")

	has, _ := svc.HasAllPermissions(ctx, "user-123", []string{"users:read", "posts:read"})
	if !has {
		t.Error("expected to have all permissions")
	}

	has, _ = svc.HasAllPermissions(ctx, "user-123", []string{"users:read", "users:delete"})
	if has {
		t.Error("should not have all permissions")
	}
}

func TestService_HasAnyPermission(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	svc.AssignRole(ctx, "user-123", "viewer")

	has, _ := svc.HasAnyPermission(ctx, "user-123", []string{"users:delete", "posts:read"})
	if !has {
		t.Error("expected to have at least one permission")
	}

	has, _ = svc.HasAnyPermission(ctx, "user-123", []string{"users:delete", "users:write"})
	if has {
		t.Error("should not have any of these permissions")
	}
}

func TestService_RequirePermission(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	svc.AssignRole(ctx, "user-123", "viewer")

	err := svc.RequirePermission(ctx, "user-123", "users:read")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = svc.RequirePermission(ctx, "user-123", "users:delete")
	if err != ErrPermissionDenied {
		t.Errorf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestService_SyncRoleTemplates(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Assign roles to users
	svc.AssignRole(ctx, "user-1", "editor")
	svc.AssignRole(ctx, "user-2", "editor")
	svc.AssignRole(ctx, "user-3", "viewer")

	// Get initial version
	perms1, _ := svc.GetUserPermissions(ctx, "user-1")
	initialVersion := perms1.PermissionVersion

	// Sync (first time stores templates)
	if err := svc.SyncRoleTemplates(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Version should not change on first sync (no changes)
	perms1After, _ := svc.GetUserPermissions(ctx, "user-1")
	if perms1After.PermissionVersion != initialVersion {
		t.Errorf("version should not change on first sync, got %d", perms1After.PermissionVersion)
	}
}

func TestService_GetConfig(t *testing.T) {
	svc := newTestService(t)
	cfg := svc.GetConfig()

	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
}

func TestService_GetAllRoles(t *testing.T) {
	svc := newTestService(t)
	roles := svc.GetAllRoles()

	if len(roles) != 3 {
		t.Errorf("expected 3 roles, got %d", len(roles))
	}
}

func TestService_GetAllPermissionGroups(t *testing.T) {
	svc := newTestService(t)
	groups := svc.GetAllPermissionGroups()

	if len(groups) != 2 {
		t.Errorf("expected 2 permission groups, got %d", len(groups))
	}
}

func TestHashPermissions(t *testing.T) {
	// Same permissions in different order should produce same hash
	hash1 := hashPermissions([]string{"a", "b", "c"})
	hash2 := hashPermissions([]string{"c", "a", "b"})

	if hash1 != hash2 {
		t.Error("same permissions should produce same hash regardless of order")
	}

	// Different permissions should produce different hash
	hash3 := hashPermissions([]string{"a", "b"})
	if hash1 == hash3 {
		t.Error("different permissions should produce different hash")
	}
}

func TestEqualPermissions(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{"same order", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different order", []string{"a", "b"}, []string{"b", "a"}, true},
		{"different length", []string{"a", "b"}, []string{"a"}, false},
		{"different content", []string{"a", "b"}, []string{"a", "c"}, false},
		{"empty", []string{}, []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := equalPermissions(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("equalPermissions(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}
