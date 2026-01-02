// Package rbac provides role-based access control functionality.
package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config defines the role-based access control configuration.
type Config struct {
	Version          int               `json:"version" yaml:"version"`
	PermissionGroups []PermissionGroup `json:"permission_groups" yaml:"permission_groups"`
	RoleTemplates    []RoleTemplate    `json:"role_templates" yaml:"role_templates"`
}

// PermissionGroup groups related permissions together.
type PermissionGroup struct {
	Name        string       `json:"name" yaml:"name"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
	Permissions []Permission `json:"permissions" yaml:"permissions"`
}

// Permission defines a single permission.
type Permission struct {
	Key         string `json:"key" yaml:"key"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// RoleTemplate defines a role template with a set of permissions.
type RoleTemplate struct {
	Key         string   `json:"key" yaml:"key"`
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Permissions []string `json:"permissions" yaml:"permissions"`
}

// Validation errors.
var (
	ErrEmptyPermissionKey      = errors.New("permission key cannot be empty")
	ErrInvalidPermissionFormat = errors.New("invalid permission format")
	ErrDuplicatePermission     = errors.New("duplicate permission key")
	ErrDuplicateRole           = errors.New("duplicate role key")
	ErrRolePermissionNotFound  = errors.New("role references undefined permission")
	ErrEmptyRoleKey            = errors.New("role key cannot be empty")
	ErrInvalidConfigPath       = errors.New("invalid config file path")
)

// LoadFromFile loads RBAC configuration from a YAML or JSON file.
// The path must be an absolute path or a relative path without directory traversal.
func LoadFromFile(path string) (*Config, error) {
	// Validate path to prevent directory traversal attacks
	if err := validateConfigPath(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is validated above
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return LoadFromBytes(data, filepath.Ext(path))
}

// validateConfigPath validates the config file path for security.
func validateConfigPath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: path cannot be empty", ErrInvalidConfigPath)
	}

	// Clean the path to resolve any . or .. components
	cleanPath := filepath.Clean(path)

	// Check for directory traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("%w: path contains directory traversal", ErrInvalidConfigPath)
	}

	// Ensure the path has a valid extension
	ext := strings.ToLower(filepath.Ext(cleanPath))
	if ext != ".yaml" && ext != ".yml" && ext != ".json" {
		return fmt.Errorf("%w: path must have .yaml, .yml, or .json extension", ErrInvalidConfigPath)
	}

	return nil
}

// LoadFromBytes parses RBAC configuration from raw bytes.
// The ext parameter should be ".yaml", ".yml", or ".json" to indicate the format.
// If empty, YAML is assumed.
func LoadFromBytes(data []byte, ext string) (*Config, error) {
	var cfg Config

	ext = strings.ToLower(ext)
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		// Default to YAML (handles .yaml, .yml, or empty)
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	}

	return &cfg, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	// Collect all valid permission keys
	validPermissions := make(map[string]bool)

	// Validate permission groups
	for _, group := range c.PermissionGroups {
		for _, perm := range group.Permissions {
			if err := validatePermissionKey(perm.Key); err != nil {
				return err
			}
			if validPermissions[perm.Key] {
				return fmt.Errorf("%w: %s", ErrDuplicatePermission, perm.Key)
			}
			validPermissions[perm.Key] = true
		}
	}

	// Validate role templates
	roleKeys := make(map[string]bool)
	for _, role := range c.RoleTemplates {
		if role.Key == "" {
			return ErrEmptyRoleKey
		}
		if roleKeys[role.Key] {
			return fmt.Errorf("%w: %s", ErrDuplicateRole, role.Key)
		}
		roleKeys[role.Key] = true

		// Check that all permissions referenced exist
		for _, permKey := range role.Permissions {
			if !isValidPermissionRef(permKey, validPermissions) {
				return fmt.Errorf("%w: role %q references %q", ErrRolePermissionNotFound, role.Key, permKey)
			}
		}
	}

	return nil
}

// validatePermissionKey checks if a permission key is valid.
func validatePermissionKey(key string) error {
	if key == "" {
		return ErrEmptyPermissionKey
	}

	// Must be in format "resource:action" or wildcards
	if key == "*" {
		return nil
	}

	parts := strings.Split(key, ":")
	if len(parts) != 2 {
		return fmt.Errorf("%w: %s (expected resource:action)", ErrInvalidPermissionFormat, key)
	}

	if parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("%w: %s (resource and action cannot be empty)", ErrInvalidPermissionFormat, key)
	}

	return nil
}

// isValidPermissionRef checks if a permission reference is valid.
// Handles wildcards like "resource:*" and "*:action".
func isValidPermissionRef(ref string, validPermissions map[string]bool) bool {
	// Direct match
	if validPermissions[ref] {
		return true
	}

	// Superuser wildcard
	if ref == "*" {
		return true
	}

	// Check for wildcard patterns
	if strings.Contains(ref, "*") {
		parts := strings.Split(ref, ":")
		if len(parts) != 2 {
			return false
		}

		// resource:* - matches any action on the resource
		if parts[1] == "*" {
			for key := range validPermissions {
				keyParts := strings.Split(key, ":")
				if len(keyParts) == 2 && keyParts[0] == parts[0] {
					return true
				}
			}
		}

		// *:action - matches the action on any resource
		if parts[0] == "*" {
			for key := range validPermissions {
				keyParts := strings.Split(key, ":")
				if len(keyParts) == 2 && keyParts[1] == parts[1] {
					return true
				}
			}
		}

		// Allow wildcard patterns even if no matching permissions exist yet
		// This supports forward-compatible configs
		return true
	}

	return false
}

// GetAllPermissions returns a flat list of all permission keys.
func (c *Config) GetAllPermissions() []string {
	var perms []string
	for _, group := range c.PermissionGroups {
		for _, perm := range group.Permissions {
			perms = append(perms, perm.Key)
		}
	}
	return perms
}

// GetRoleTemplate returns a role template by key, or nil if not found.
func (c *Config) GetRoleTemplate(key string) *RoleTemplate {
	for i := range c.RoleTemplates {
		if c.RoleTemplates[i].Key == key {
			return &c.RoleTemplates[i]
		}
	}
	return nil
}

// GetPermission returns a permission by key, or nil if not found.
func (c *Config) GetPermission(key string) *Permission {
	for _, group := range c.PermissionGroups {
		for i := range group.Permissions {
			if group.Permissions[i].Key == key {
				return &group.Permissions[i]
			}
		}
	}
	return nil
}

// ExpandWildcards expands wildcard permissions to concrete permissions.
func (c *Config) ExpandWildcards(perms []string) []string {
	allPerms := c.GetAllPermissions()
	expanded := make(map[string]bool)

	for _, perm := range perms {
		if perm == "*" {
			// Superuser - add all permissions
			for _, p := range allPerms {
				expanded[p] = true
			}
			continue
		}

		if strings.Contains(perm, "*") {
			parts := strings.Split(perm, ":")
			if len(parts) != 2 {
				expanded[perm] = true
				continue
			}

			for _, p := range allPerms {
				pParts := strings.Split(p, ":")
				if len(pParts) != 2 {
					continue
				}

				// resource:* matches
				if parts[1] == "*" && parts[0] == pParts[0] {
					expanded[p] = true
				}
				// *:action matches
				if parts[0] == "*" && parts[1] == pParts[1] {
					expanded[p] = true
				}
			}
		} else {
			expanded[perm] = true
		}
	}

	result := make([]string, 0, len(expanded))
	for p := range expanded {
		result = append(result, p)
	}
	return result
}
