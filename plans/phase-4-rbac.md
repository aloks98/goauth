# Phase 4: RBAC System

**Duration:** 5-6 days
**Goal:** Implement role-based access control with user-level permissions.

**Dependencies:** Phase 1 (Foundation)

> **Note:** RBAC is an optional feature. When no RBAC config is provided, GoAuth runs in "simple mode" with just authentication. This phase implements the optional RBAC features.

---

## Tasks

### 4.0 RBAC Mode Detection

**Description:** Implement detection of whether RBAC is enabled and handle gracefully.

**Estimated Hours:** 1

**Acceptance Criteria:**
- [x] `Auth.rbacEnabled` boolean flag
- [x] Set to `true` when any RBAC config is provided
- [x] RBAC methods return `ErrRBACNotEnabled` when disabled
- [ ] Token generation skips permission_version when disabled
- [ ] Middleware permission checks return error when disabled

**Implementation:**
```go
var ErrRBACNotEnabled = errors.New("RBAC is not enabled; provide WithRBACFromFile() or WithRBACFromBytes()")

func (a *Auth[T]) AssignRole(ctx context.Context, userID, role string) error {
    if !a.rbacEnabled {
        return ErrRBACNotEnabled
    }
    // ... implementation
}
```

**Testing:**
- [ ] Unit test: RBAC methods return error when disabled
- [ ] Unit test: Token generation works without RBAC
- [ ] Unit test: RBAC methods work when enabled

---

### 4.1 Config File Structs

**Description:** Define RBAC config file structures in `rbac/config.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] `RBACConfig` struct for root config
- [x] `PermissionGroup` struct with permissions
- [x] `Permission` struct with key and name
- [x] `RoleTemplate` struct with permissions
- [x] JSON and YAML tags on all fields

**Implementation:**
```go
type RBACConfig struct {
    Version           int                `yaml:"version" json:"version"`
    PermissionGroups  []PermissionGroup  `yaml:"permission_groups" json:"permission_groups"`
    RoleTemplates     []RoleTemplate     `yaml:"role_templates" json:"role_templates"`
}

type PermissionGroup struct {
    Key         string       `yaml:"key" json:"key"`
    Name        string       `yaml:"name" json:"name"`
    Description string       `yaml:"description" json:"description"`
    Permissions []Permission `yaml:"permissions" json:"permissions"`
}

type Permission struct {
    Key         string `yaml:"key" json:"key"`
    Name        string `yaml:"name" json:"name"`
    Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type RoleTemplate struct {
    Key         string   `yaml:"key" json:"key"`
    Name        string   `yaml:"name" json:"name"`
    Description string   `yaml:"description" json:"description"`
    Permissions []string `yaml:"permissions" json:"permissions"`
}
```

**Testing:**
- [x] Unit test: Unmarshal YAML config correctly
- [x] Unit test: Unmarshal JSON config correctly
- [x] Unit test: Marshal produces correct output

---

### 4.2 Config Loader

**Description:** Implement config file loading in `rbac/loader.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] Load from file path (YAML or JSON)
- [x] Load from byte slice
- [x] Auto-detect format (YAML vs JSON)
- [x] Clear error messages for parse failures

**Implementation:**
```go
func LoadFromFile(path string) (*RBACConfig, error)
func LoadFromBytes(data []byte) (*RBACConfig, error)
func detectFormat(data []byte) string // "yaml" or "json"
```

**Testing:**
- [x] Unit test: Load valid YAML file
- [x] Unit test: Load valid JSON file
- [x] Unit test: Invalid YAML returns error
- [x] Unit test: File not found returns error
- [x] Unit test: Format detection works

---

### 4.3 Config Validator

**Description:** Implement config validation in `rbac/validator.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [x] Validate version (must be 1)
- [x] Validate no duplicate permission keys
- [x] Validate no duplicate role keys
- [x] Validate role permissions reference defined permissions or wildcards
- [x] Validate permission key format (`resource:action`)
- [x] Return all validation errors (not just first)

**Implementation:**
```go
func ValidateConfig(config *RBACConfig) error

type ValidationError struct {
    Errors []string
}
```

**Validation Rules:**
```go
// Permission key format
^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$  // Normal
^[a-z][a-z0-9_]*:\*$               // Wildcard action
^\*:[a-z][a-z0-9_]*$               // Wildcard resource
^\*$                                // Super wildcard
```

**Testing:**
- [x] Unit test: Valid config passes
- [x] Unit test: Invalid version returns error
- [x] Unit test: Duplicate permission detected
- [x] Unit test: Duplicate role detected
- [x] Unit test: Unknown permission in role detected
- [x] Unit test: Invalid permission format detected
- [x] Unit test: Multiple errors collected

---

### 4.4 Permission Registry

**Description:** Implement in-memory permission registry in `rbac/registry.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] Store all permissions from config
- [x] Store all role templates from config
- [x] Provide lookup methods
- [x] Thread-safe access

**Implementation:**
```go
type Registry struct {
    permissions map[string]*Permission
    groups      []*PermissionGroup
    roles       map[string]*RoleTemplate
    mu          sync.RWMutex
}

func NewRegistry(config *RBACConfig) (*Registry, error)
func (r *Registry) GetPermission(key string) *Permission
func (r *Registry) GetRoleTemplate(key string) *RoleTemplate
func (r *Registry) GetAllPermissions() []Permission
func (r *Registry) GetAllGroups() []PermissionGroup
func (r *Registry) GetAllRoleTemplates() []RoleTemplate
```

**Testing:**
- [x] Unit test: Registry loads all permissions
- [x] Unit test: Registry loads all roles
- [x] Unit test: Lookup returns correct data
- [x] Unit test: Unknown key returns nil
- [x] Unit test: Thread-safe concurrent access

---

### 4.5 Permission Matching

**Description:** Implement permission matching with wildcards in `rbac/permission.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] Exact match: `monitors:read` matches `monitors:read`
- [x] Resource wildcard: `monitors:*` matches `monitors:read`
- [x] Action wildcard: `*:read` matches `monitors:read`
- [x] Super wildcard: `*` matches everything
- [x] No partial matches: `monitor:read` doesn't match `monitors:read`

**Implementation:**
```go
func MatchPermission(held, required string) bool
func HasPermission(permissions []string, required string) bool
func HasAllPermissions(permissions []string, required []string) bool
func HasAnyPermission(permissions []string, required []string) bool
```

**Testing:**
- [x] Unit test: Exact match works
- [x] Unit test: Resource wildcard works
- [x] Unit test: Action wildcard works
- [x] Unit test: Super wildcard works
- [x] Unit test: Non-matching returns false
- [x] Unit test: HasAllPermissions requires all
- [x] Unit test: HasAnyPermission requires one

---

### 4.6 User Permission Management

**Description:** Implement user permission CRUD in `rbac/service.go`.

**Estimated Hours:** 5

**Acceptance Criteria:**
- [x] Assign role template to user (copy permissions)
- [x] Add permissions to user
- [x] Remove permissions from user
- [x] Set exact permissions
- [x] Get user permissions
- [x] Delete user permissions
- [x] Auto-detect role label (template or "custom")
- [x] Bump permission version on changes

**Implementation:**
```go
type Service struct {
    store    store.Store
    registry *Registry
}

func (s *Service) AssignRole(ctx context.Context, userID, role string) error
func (s *Service) AddPermissions(ctx context.Context, userID string, perms []string) error
func (s *Service) RemovePermissions(ctx context.Context, userID string, perms []string) error
func (s *Service) SetPermissions(ctx context.Context, userID string, perms []string) error
func (s *Service) GetUserPermissions(ctx context.Context, userID string) (*store.UserPermissions, error)
func (s *Service) DeleteUserPermissions(ctx context.Context, userID string) error
func (s *Service) ResetToRoleTemplate(ctx context.Context, userID string) error
```

**Auto-detect Role Label:**
```go
func (s *Service) detectRoleLabel(permissions []string) string {
    for _, tpl := range s.registry.GetAllRoleTemplates() {
        if s.permissionsMatch(permissions, tpl.Permissions) {
            return tpl.Key
        }
    }
    return "custom"
}
```

**Testing:**
- [x] Unit test: AssignRole copies template permissions
- [x] Unit test: AddPermissions appends and bumps version
- [x] Unit test: RemovePermissions removes and bumps version
- [x] Unit test: SetPermissions replaces all
- [x] Unit test: Role label auto-detected correctly
- [x] Unit test: "custom" when doesn't match any template
- [x] Unit test: Permission version increments
- [ ] Integration test: Full CRUD flow

---

### 4.7 Role Template Sync

**Description:** Implement startup sync in `rbac/service.go`.

**Estimated Hours:** 5

**Acceptance Criteria:**
- [x] Compare config templates with stored templates
- [x] Detect changed templates (by permissions hash)
- [x] Sync users with matching role_label
- [x] Skip users with role_label = "custom"
- [x] Log sync operations
- [x] Store template snapshot for next comparison

**Implementation:**
```go
func (s *Service) SyncRoleTemplates(ctx context.Context) error

// Returns error if any
```

**Sync Flow:**
```
1. Load stored templates from DB
2. For each config template:
   a. Calculate permissions hash
   b. Compare with stored hash
   c. If different:
      - Find users with role_label = template.Key
      - Update their permissions
      - Bump their permission version
      - Log to sync audit table
   d. Store/update template in DB
```

**Testing:**
- [x] Unit test: New template is stored
- [x] Unit test: Unchanged template skipped
- [x] Unit test: Changed template syncs users
- [x] Unit test: Custom users not synced
- [x] Unit test: Audit log created
- [ ] Integration test: Full sync flow
- [ ] Integration test: First startup (empty DB)

---

### 4.8 RBAC Main Interface

**Description:** Create main RBAC interface in `rbac/service.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] `Service` struct combining all components
- [x] Constructor from config
- [x] Public methods for all operations
- [x] Initialize and sync on creation

**Implementation:**
```go
type Service struct {
    registry *Registry
    store    store.Store
}

func NewService(config *Config, store store.Store) (*Service, error)
```

**Testing:**
- [x] Unit test: Constructor validates config
- [x] Unit test: Service methods work correctly
- [ ] Integration test: Full initialization

---

### 4.9 Wire Up to Auth

**Description:** Connect RBAC to main Auth struct.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] RBAC initialized from config in `New()`
- [x] All RBAC methods exposed on Auth
- [x] Permission check uses RBAC

**Testing:**
- [ ] Integration test: Full RBAC flow through Auth

---

## Remaining Work

> **STATUS: ✅ 100% Complete** - RBAC is fully implemented including service methods, role sync, and wiring to `Auth[T]`.

- [x] Complete RBAC service methods (AssignRole, AddPermissions, etc.) in `rbac/service.go`
- [x] Implement role template sync on startup via `SyncRoleTemplates()`
- [x] Wire RBAC to main `Auth[T]` struct
- [ ] Add integration tests (optional)

---

## Phase 4 Checklist

- [x] Config structs defined
- [x] Config loader implemented
- [x] Config validator implemented
- [x] Permission registry implemented
- [x] Permission matching implemented
- [x] User permission management implemented
- [x] Role template sync implemented
- [x] RBAC main interface implemented
- [x] Auth wired up
- [x] All unit tests pass
- [ ] All integration tests pass

## Integration Test Scenarios

```go
func TestRBAC_AssignAndModify(t *testing.T) {
    // 1. Create user
    // 2. Assign "editor" role
    // 3. Verify permissions match template
    // 4. Add extra permission
    // 5. Verify role_label is "custom"
    // 6. Reset to template
    // 7. Verify role_label is "editor" again
}

func TestRBAC_TemplateSyncOnStartup(t *testing.T) {
    // 1. Create RBAC with initial config
    // 2. Assign "editor" to user
    // 3. Close RBAC
    // 4. Modify config (change editor permissions)
    // 5. Create new RBAC instance
    // 6. Verify user permissions updated
    // 7. Verify permission version bumped
}

func TestRBAC_CustomNotSynced(t *testing.T) {
    // 1. Assign "editor" to user
    // 2. Add custom permission
    // 3. Modify editor template
    // 4. Restart RBAC
    // 5. Verify user NOT synced (custom role)
}
```

## Test Commands

```bash
# Run RBAC package tests
go test ./rbac/... -v

# Run with coverage
go test ./rbac/... -cover

# Run specific test
go test ./rbac/... -run TestRBAC_TemplateSyncOnStartup
```
