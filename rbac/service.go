package rbac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/aloks98/goauth/store"
)

// Service errors.
var (
	ErrRBACNotEnabled          = errors.New("RBAC is not enabled")
	ErrRoleNotFound            = errors.New("role not found")
	ErrPermissionDenied        = errors.New("permission denied")
	ErrUserPermissionsNotFound = errors.New("user permissions not found")
)

// Service handles RBAC operations.
type Service struct {
	config *Config
	store  store.Store
}

// NewService creates a new RBAC service.
func NewService(cfg *Config, s store.Store) (*Service, error) {
	if cfg == nil {
		return nil, ErrRBACNotEnabled
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Service{
		config: cfg,
		store:  s,
	}, nil
}

// GetConfig returns the RBAC configuration.
func (s *Service) GetConfig() *Config {
	return s.config
}

// AssignRole assigns a role template to a user.
// This copies the role's permissions to the user and sets the role label.
func (s *Service) AssignRole(ctx context.Context, userID, roleKey string) error {
	role := s.config.GetRoleTemplate(roleKey)
	if role == nil {
		return ErrRoleNotFound
	}

	// Expand wildcards in role permissions
	permissions := s.config.ExpandWildcards(role.Permissions)

	// Get existing permissions to determine new version
	existing, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return err
	}

	version := 1
	if existing != nil {
		version = existing.PermissionVersion + 1
	}

	perms := &store.UserPermissions{
		UserID:            userID,
		RoleLabel:         roleKey,
		BaseRole:          roleKey,
		Permissions:       permissions,
		PermissionVersion: version,
		UpdatedAt:         time.Now(),
	}

	return s.store.SaveUserPermissions(ctx, perms)
}

// AddPermissions adds permissions to a user without changing their role.
// This marks them as "custom" if they were previously on a role template.
func (s *Service) AddPermissions(ctx context.Context, userID string, permissions []string) error {
	existing, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return err
	}

	if existing == nil {
		// Create new permission record
		existing = &store.UserPermissions{
			UserID:            userID,
			RoleLabel:         "custom",
			Permissions:       []string{},
			PermissionVersion: 0,
		}
	}

	// Add new permissions (deduplicated)
	permSet := make(map[string]bool)
	for _, p := range existing.Permissions {
		permSet[p] = true
	}
	for _, p := range permissions {
		permSet[p] = true
	}

	newPerms := make([]string, 0, len(permSet))
	for p := range permSet {
		newPerms = append(newPerms, p)
	}
	sort.Strings(newPerms)

	existing.Permissions = newPerms
	existing.PermissionVersion++
	existing.UpdatedAt = time.Now()

	// Mark as custom if permissions differ from base role
	if existing.BaseRole != "" {
		role := s.config.GetRoleTemplate(existing.BaseRole)
		if role != nil {
			rolePerms := s.config.ExpandWildcards(role.Permissions)
			if !equalPermissions(newPerms, rolePerms) {
				existing.RoleLabel = "custom"
			}
		}
	}

	return s.store.SaveUserPermissions(ctx, existing)
}

// RemovePermissions removes permissions from a user.
func (s *Service) RemovePermissions(ctx context.Context, userID string, permissions []string) error {
	existing, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return err
	}

	if existing == nil {
		return nil // Nothing to remove
	}

	// Remove specified permissions
	removeSet := make(map[string]bool)
	for _, p := range permissions {
		removeSet[p] = true
	}

	newPerms := make([]string, 0)
	for _, p := range existing.Permissions {
		if !removeSet[p] {
			newPerms = append(newPerms, p)
		}
	}

	existing.Permissions = newPerms
	existing.PermissionVersion++
	existing.UpdatedAt = time.Now()

	// Mark as custom if they had a base role
	if existing.BaseRole != "" {
		existing.RoleLabel = "custom"
	}

	return s.store.SaveUserPermissions(ctx, existing)
}

// SetPermissions sets a user's permissions directly.
func (s *Service) SetPermissions(ctx context.Context, userID string, permissions []string) error {
	existing, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return err
	}

	version := 1
	baseRole := ""
	if existing != nil {
		version = existing.PermissionVersion + 1
		baseRole = existing.BaseRole
	}

	perms := &store.UserPermissions{
		UserID:            userID,
		RoleLabel:         "custom",
		BaseRole:          baseRole,
		Permissions:       permissions,
		PermissionVersion: version,
		UpdatedAt:         time.Now(),
	}

	return s.store.SaveUserPermissions(ctx, perms)
}

// ResetToRole resets a user's permissions to match their base role.
func (s *Service) ResetToRole(ctx context.Context, userID string) error {
	existing, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return err
	}

	if existing == nil || existing.BaseRole == "" {
		return ErrRoleNotFound
	}

	return s.AssignRole(ctx, userID, existing.BaseRole)
}

// GetUserPermissions returns a user's permissions.
func (s *Service) GetUserPermissions(ctx context.Context, userID string) (*store.UserPermissions, error) {
	return s.store.GetUserPermissions(ctx, userID)
}

// HasPermission checks if a user has a specific permission.
func (s *Service) HasPermission(ctx context.Context, userID, permission string) (bool, error) {
	perms, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	if perms == nil {
		return false, nil
	}

	return perms.HasPermission(permission), nil
}

// HasAllPermissions checks if a user has all specified permissions.
func (s *Service) HasAllPermissions(ctx context.Context, userID string, permissions []string) (bool, error) {
	perms, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	if perms == nil {
		return false, nil
	}

	return perms.HasAllPermissions(permissions), nil
}

// HasAnyPermission checks if a user has any of the specified permissions.
func (s *Service) HasAnyPermission(ctx context.Context, userID string, permissions []string) (bool, error) {
	perms, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	if perms == nil {
		return false, nil
	}

	return perms.HasAnyPermission(permissions), nil
}

// RequirePermission returns an error if the user doesn't have the permission.
func (s *Service) RequirePermission(ctx context.Context, userID, permission string) error {
	has, err := s.HasPermission(ctx, userID, permission)
	if err != nil {
		return err
	}

	if !has {
		return ErrPermissionDenied
	}

	return nil
}

// SyncRoleTemplates synchronizes role template changes to affected users.
// This should be called on startup when role templates have changed.
func (s *Service) SyncRoleTemplates(ctx context.Context) error {
	// Get stored templates
	storedTemplates, err := s.store.GetRoleTemplates(ctx)
	if err != nil {
		return err
	}

	// Check each role template for changes
	for _, role := range s.config.RoleTemplates {
		stored, exists := storedTemplates[role.Key]

		// Expand wildcards for current role
		currentPerms := s.config.ExpandWildcards(role.Permissions)
		currentHash := hashPermissions(currentPerms)

		if !exists || stored.PermissionHash != currentHash {
			// Role template changed - update all users with this role
			newVersion := 1
			if stored != nil {
				newVersion = stored.Version + 1
			}

			// Update users
			_, err := s.store.UpdateUsersWithRole(ctx, role.Key, currentPerms, newVersion)
			if err != nil {
				return err
			}

			// Save the new template snapshot
			template := &store.StoredRoleTemplate{
				Key:            role.Key,
				PermissionHash: currentHash,
				Version:        newVersion,
				Permissions:    currentPerms,
				UpdatedAt:      time.Now(),
			}
			if err := s.store.SaveRoleTemplate(ctx, template); err != nil {
				return err
			}
		}
	}

	return nil
}

// hashPermissions creates a hash of a sorted permission list.
func hashPermissions(perms []string) string {
	sorted := make([]string, len(perms))
	copy(sorted, perms)
	sort.Strings(sorted)

	h := sha256.New()
	for _, p := range sorted {
		h.Write([]byte(p))
		h.Write([]byte{0}) // separator
	}
	return hex.EncodeToString(h.Sum(nil))
}

// equalPermissions checks if two permission slices are equal.
func equalPermissions(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	sortedA := make([]string, len(a))
	copy(sortedA, a)
	sort.Strings(sortedA)

	sortedB := make([]string, len(b))
	copy(sortedB, b)
	sort.Strings(sortedB)

	for i := range sortedA {
		if sortedA[i] != sortedB[i] {
			return false
		}
	}
	return true
}

// GetAllRoles returns all role templates.
func (s *Service) GetAllRoles() []RoleTemplate {
	return s.config.RoleTemplates
}

// GetAllPermissionGroups returns all permission groups.
func (s *Service) GetAllPermissionGroups() []PermissionGroup {
	return s.config.PermissionGroups
}
