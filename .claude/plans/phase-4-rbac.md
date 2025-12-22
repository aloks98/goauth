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
- [ ] `Auth.rbacEnabled` boolean flag
- [ ] Set to `true` when any RBAC config is provided
- [ ] RBAC methods return `ErrRBACNotEnabled` when disabled
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
- [ ] `RBACConfig` struct for root config
- [ ] `PermissionGroup` struct with permissions
- [ ] `Permission` struct with key and name
- [ ] `RoleTemplate` struct with permissions
- [ ] JSON and YAML tags on all fields

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
- [ ] Unit test: Unmarshal YAML config correctly
- [ ] Unit test: Unmarshal JSON config correctly
- [ ] Unit test: Marshal produces correct output

---

### 4.2 Config Loader

**Description:** Implement config file loading in `rbac/loader.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [ ] Load from file path (YAML or JSON)
- [ ] Load from byte slice
- [ ] Auto-detect format (YAML vs JSON)
- [ ] Clear error messages for parse failures

**Implementation:**
```go
func LoadFromFile(path string) (*RBACConfig, error)
func LoadFromBytes(data []byte) (*RBACConfig, error)
func detectFormat(data []byte) string // "yaml" or "json"
```

**Testing:**
- [ ] Unit test: Load valid YAML file
- [ ] Unit test: Load valid JSON file
- [ ] Unit test: Invalid YAML returns error
- [ ] Unit test: File not found returns error
- [ ] Unit test: Format detection works

---

### 4.3 Config Validator

**Description:** Implement config validation in `rbac/validator.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [ ] Validate version (must be 1)
- [ ] Validate no duplicate permission keys
- [ ] Validate no duplicate role keys
- [ ] Validate role permissions reference defined permissions or wildcards
- [ ] Validate permission key format (`resource:action`)
- [ ] Return all validation errors (not just first)

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
- [ ] Unit test: Valid config passes
- [ ] Unit test: Invalid version returns error
- [ ] Unit test: Duplicate permission detected
- [ ] Unit test: Duplicate role detected
- [ ] Unit test: Unknown permission in role detected
- [ ] Unit test: Invalid permission format detected
- [ ] Unit test: Multiple errors collected

---

### 4.4 Permission Registry

**Description:** Implement in-memory permission registry in `rbac/registry.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [ ] Store all permissions from config
- [ ] Store all role templates from config
- [ ] Provide lookup methods
- [ ] Thread-safe access

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
- [ ] Unit test: Registry loads all permissions
- [ ] Unit test: Registry loads all roles
- [ ] Unit test: Lookup returns correct data
- [ ] Unit test: Unknown key returns nil
- [ ] Unit test: Thread-safe concurrent access

---

### 4.5 Permission Matching

**Description:** Implement permission matching with wildcards in `rbac/permission.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [ ] Exact match: `monitors:read` matches `monitors:read`
- [ ] Resource wildcard: `monitors:*` matches `monitors:read`
- [ ] Action wildcard: `*:read` matches `monitors:read`
- [ ] Super wildcard: `*` matches everything
- [ ] No partial matches: `monitor:read` doesn't match `monitors:read`

**Implementation:**
```go
func MatchPermission(held, required string) bool
func HasPermission(permissions []string, required string) bool
func HasAllPermissions(permissions []string, required []string) bool
func HasAnyPermission(permissions []string, required []string) bool
```

**Testing:**
- [ ] Unit test: Exact match works
- [ ] Unit test: Resource wildcard works
- [ ] Unit test: Action wildcard works
- [ ] Unit test: Super wildcard works
- [ ] Unit test: Non-matching returns false
- [ ] Unit test: HasAllPermissions requires all
- [ ] Unit test: HasAnyPermission requires one

---

### 4.6 User Permission Management

**Description:** Implement user permission CRUD in `rbac/resolver.go`.

**Estimated Hours:** 5

**Acceptance Criteria:**
- [ ] Assign role template to user (copy permissions)
- [ ] Add permissions to user
- [ ] Remove permissions from user
- [ ] Set exact permissions
- [ ] Get user permissions
- [ ] Delete user permissions
- [ ] Auto-detect role label (template or "custom")
- [ ] Bump permission version on changes

**Implementation:**
```go
type Resolver struct {
    store    Store
    registry *Registry
}

func (r *Resolver) AssignRole(ctx context.Context, userID, role string) error
func (r *Resolver) AddPermissions(ctx context.Context, userID string, perms []string) error
func (r *Resolver) RemovePermissions(ctx context.Context, userID string, perms []string) error
func (r *Resolver) SetPermissions(ctx context.Context, userID string, perms []string) error
func (r *Resolver) GetUserPermissions(ctx context.Context, userID string) (*UserPermissions, error)
func (r *Resolver) DeleteUserPermissions(ctx context.Context, userID string) error
func (r *Resolver) ResetToRoleTemplate(ctx context.Context, userID string) error
```

**Auto-detect Role Label:**
```go
func (r *Resolver) detectRoleLabel(permissions []string) string {
    for _, tpl := range r.registry.GetAllRoleTemplates() {
        if r.permissionsMatch(permissions, tpl.Permissions) {
            return tpl.Key
        }
    }
    return "custom"
}
```

**Testing:**
- [ ] Unit test: AssignRole copies template permissions
- [ ] Unit test: AddPermissions appends and bumps version
- [ ] Unit test: RemovePermissions removes and bumps version
- [ ] Unit test: SetPermissions replaces all
- [ ] Unit test: Role label auto-detected correctly
- [ ] Unit test: "custom" when doesn't match any template
- [ ] Unit test: Permission version increments
- [ ] Integration test: Full CRUD flow

---

### 4.7 Role Template Sync

**Description:** Implement startup sync in `rbac/sync.go`.

**Estimated Hours:** 5

**Acceptance Criteria:**
- [ ] Compare config templates with stored templates
- [ ] Detect changed templates (by permissions hash)
- [ ] Sync users with matching role_label
- [ ] Skip users with role_label = "custom"
- [ ] Log sync operations
- [ ] Store template snapshot for next comparison

**Implementation:**
```go
type Syncer struct {
    store    Store
    registry *Registry
    logger   Logger
}

func (s *Syncer) SyncRoleTemplates(ctx context.Context) error

// Returns:
// - Number of templates changed
// - Number of users updated
// - Error if any
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
- [ ] Unit test: New template is stored
- [ ] Unit test: Unchanged template skipped
- [ ] Unit test: Changed template syncs users
- [ ] Unit test: Custom users not synced
- [ ] Unit test: Audit log created
- [ ] Integration test: Full sync flow
- [ ] Integration test: First startup (empty DB)

---

### 4.8 RBAC Main Interface

**Description:** Create main RBAC interface in `rbac/rbac.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [ ] `RBAC` struct combining all components
- [ ] Constructor from config
- [ ] Public methods for all operations
- [ ] Initialize and sync on creation

**Implementation:**
```go
type RBAC struct {
    registry *Registry
    resolver *Resolver
    syncer   *Syncer
}

func New(config *RBACConfig, store Store, opts ...Option) (*RBAC, error)
func NewFromFile(path string, store Store, opts ...Option) (*RBAC, error)
func NewFromBytes(data []byte, store Store, opts ...Option) (*RBAC, error)
```

**Testing:**
- [ ] Unit test: Constructor validates config
- [ ] Unit test: Sync runs on creation
- [ ] Integration test: Full initialization

---

### 4.9 Wire Up to Auth

**Description:** Connect RBAC to main Auth struct.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [ ] RBAC initialized from config in `New()`
- [ ] All RBAC methods exposed on Auth
- [ ] Permission check uses RBAC

**Testing:**
- [ ] Integration test: Full RBAC flow through Auth

---

## Phase 4 Checklist

- [ ] Config structs defined
- [ ] Config loader implemented
- [ ] Config validator implemented
- [ ] Permission registry implemented
- [ ] Permission matching implemented
- [ ] User permission management implemented
- [ ] Role template sync implemented
- [ ] RBAC main interface implemented
- [ ] Auth wired up
- [ ] All unit tests pass
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
