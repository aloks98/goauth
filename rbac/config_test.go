package rbac

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromBytes_YAML(t *testing.T) {
	yamlData := `
version: 1
permission_groups:
  - name: Users
    permissions:
      - key: users:read
        name: Read Users
      - key: users:write
        name: Write Users
  - name: Posts
    permissions:
      - key: posts:read
        name: Read Posts
      - key: posts:write
        name: Write Posts
role_templates:
  - key: admin
    name: Administrator
    permissions:
      - "*"
  - key: editor
    name: Editor
    permissions:
      - users:read
      - posts:*
`

	cfg, err := LoadFromBytes([]byte(yamlData), ".yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}

	if len(cfg.PermissionGroups) != 2 {
		t.Errorf("expected 2 permission groups, got %d", len(cfg.PermissionGroups))
	}

	if len(cfg.RoleTemplates) != 2 {
		t.Errorf("expected 2 role templates, got %d", len(cfg.RoleTemplates))
	}
}

func TestLoadFromBytes_JSON(t *testing.T) {
	jsonData := `{
		"version": 1,
		"permission_groups": [
			{
				"name": "Users",
				"permissions": [
					{"key": "users:read", "name": "Read Users"}
				]
			}
		],
		"role_templates": [
			{
				"key": "viewer",
				"name": "Viewer",
				"permissions": ["users:read"]
			}
		]
	}`

	cfg, err := LoadFromBytes([]byte(jsonData), ".json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}

	if len(cfg.PermissionGroups) != 1 {
		t.Errorf("expected 1 permission group, got %d", len(cfg.PermissionGroups))
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "config.yaml")

	yamlData := `
version: 1
permission_groups:
  - name: Test
    permissions:
      - key: test:read
        name: Read Test
role_templates:
  - key: tester
    name: Tester
    permissions:
      - test:read
`
	if err := os.WriteFile(yamlPath, []byte(yamlData), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	cfg, err := LoadFromFile(yamlPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "users:read", Name: "Read"},
							{Key: "users:write", Name: "Write"},
						},
					},
				},
				RoleTemplates: []RoleTemplate{
					{Key: "admin", Name: "Admin", Permissions: []string{"users:read", "users:write"}},
				},
			},
			wantErr: false,
		},
		{
			name: "empty permission key",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "", Name: "Empty"},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid permission format",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "invalid", Name: "Invalid"},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate permission",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "users:read", Name: "Read 1"},
							{Key: "users:read", Name: "Read 2"},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate role",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "users:read", Name: "Read"},
						},
					},
				},
				RoleTemplates: []RoleTemplate{
					{Key: "admin", Name: "Admin 1", Permissions: []string{"users:read"}},
					{Key: "admin", Name: "Admin 2", Permissions: []string{"users:read"}},
				},
			},
			wantErr: true,
		},
		{
			name: "empty role key",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "users:read", Name: "Read"},
						},
					},
				},
				RoleTemplates: []RoleTemplate{
					{Key: "", Name: "No Key", Permissions: []string{"users:read"}},
				},
			},
			wantErr: true,
		},
		{
			name: "role references undefined permission",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "users:read", Name: "Read"},
						},
					},
				},
				RoleTemplates: []RoleTemplate{
					{Key: "admin", Name: "Admin", Permissions: []string{"posts:write"}},
				},
			},
			wantErr: true,
		},
		{
			name: "wildcard permission is valid",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "users:read", Name: "Read"},
						},
					},
				},
				RoleTemplates: []RoleTemplate{
					{Key: "admin", Name: "Admin", Permissions: []string{"*"}},
				},
			},
			wantErr: false,
		},
		{
			name: "resource wildcard is valid",
			config: &Config{
				PermissionGroups: []PermissionGroup{
					{
						Name: "Users",
						Permissions: []Permission{
							{Key: "users:read", Name: "Read"},
							{Key: "users:write", Name: "Write"},
						},
					},
				},
				RoleTemplates: []RoleTemplate{
					{Key: "user-admin", Name: "User Admin", Permissions: []string{"users:*"}},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_GetAllPermissions(t *testing.T) {
	cfg := &Config{
		PermissionGroups: []PermissionGroup{
			{
				Name: "Users",
				Permissions: []Permission{
					{Key: "users:read"},
					{Key: "users:write"},
				},
			},
			{
				Name: "Posts",
				Permissions: []Permission{
					{Key: "posts:read"},
				},
			},
		},
	}

	perms := cfg.GetAllPermissions()
	if len(perms) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(perms))
	}
}

func TestConfig_GetRoleTemplate(t *testing.T) {
	cfg := &Config{
		RoleTemplates: []RoleTemplate{
			{Key: "admin", Name: "Administrator"},
			{Key: "editor", Name: "Editor"},
		},
	}

	role := cfg.GetRoleTemplate("admin")
	if role == nil {
		t.Fatal("expected to find admin role")
	}
	if role.Name != "Administrator" {
		t.Errorf("expected name Administrator, got %s", role.Name)
	}

	role = cfg.GetRoleTemplate("nonexistent")
	if role != nil {
		t.Error("expected nil for nonexistent role")
	}
}

func TestConfig_GetPermission(t *testing.T) {
	cfg := &Config{
		PermissionGroups: []PermissionGroup{
			{
				Name: "Users",
				Permissions: []Permission{
					{Key: "users:read", Name: "Read Users"},
				},
			},
		},
	}

	perm := cfg.GetPermission("users:read")
	if perm == nil {
		t.Fatal("expected to find permission")
	}
	if perm.Name != "Read Users" {
		t.Errorf("expected name 'Read Users', got %s", perm.Name)
	}

	perm = cfg.GetPermission("nonexistent")
	if perm != nil {
		t.Error("expected nil for nonexistent permission")
	}
}

func TestConfig_ExpandWildcards(t *testing.T) {
	cfg := &Config{
		PermissionGroups: []PermissionGroup{
			{
				Name: "Users",
				Permissions: []Permission{
					{Key: "users:read"},
					{Key: "users:write"},
					{Key: "users:delete"},
				},
			},
			{
				Name: "Posts",
				Permissions: []Permission{
					{Key: "posts:read"},
					{Key: "posts:write"},
				},
			},
		},
	}

	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{"superuser wildcard", []string{"*"}, 5},
		{"resource wildcard", []string{"users:*"}, 3},
		{"action wildcard", []string{"*:read"}, 2},
		{"specific permissions", []string{"users:read", "posts:write"}, 2},
		{"mixed", []string{"users:*", "posts:read"}, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.ExpandWildcards(tt.input)
			if len(result) != tt.expected {
				t.Errorf("expected %d permissions, got %d: %v", tt.expected, len(result), result)
			}
		})
	}
}

func TestValidatePermissionKey(t *testing.T) {
	tests := []struct {
		key     string
		wantErr bool
	}{
		{"users:read", false},
		{"posts:write", false},
		{"*", false},
		{"users:*", false},
		{"*:read", false},
		{"", true},
		{"nocolon", true},
		{":action", true},
		{"resource:", true},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := validatePermissionKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePermissionKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}
