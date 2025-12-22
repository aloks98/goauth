# RBAC System

## Overview

GoAuth implements a flexible RBAC system where permissions are assigned at the user level, with role templates serving as convenient presets.

## Key Concepts

| Concept | Description |
|---------|-------------|
| Permission | Atomic access right (e.g., `monitors:read`) |
| Permission Group | Logical grouping for UI (e.g., "Monitors") |
| Role Template | Predefined permission set (e.g., "editor") |
| User Permissions | Actual permissions assigned to a user |
| Role Label | Display name: matches template or "custom" |
| Permission Version | Incremented when user's permissions change |

## Permission Format

```
resource:action
resource:action:scope
```

**Examples:**

```
monitors:read           # Read monitors
monitors:write          # Create/edit monitors
monitors:delete         # Delete monitors
monitors:*              # All monitor actions (wildcard)
alerts:read:own         # Read own alerts only
alerts:read:team        # Read team's alerts
*:read                  # Read anything
*                       # Superuser (all permissions)
```

## Wildcard Matching

```go
// Permission matching rules
"monitors:*"    matches "monitors:read", "monitors:write", "monitors:delete"
"*:read"        matches "monitors:read", "alerts:read", "users:read"
"*"             matches everything
"monitors:read" matches only "monitors:read"
```

## User Permission Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    Permission Assignment                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ROLE TEMPLATES (presets, defined in config)                    │
│  ──────────────────────────────────────────                     │
│                                                                  │
│  viewer → [monitors:read, alerts:read]                          │
│  editor → [monitors:read, monitors:write, alerts:*]             │
│  admin  → [monitors:*, alerts:*, users:read, users:write]       │
│  owner  → [*]                                                    │
│                                                                  │
│  USER PERMISSIONS (actual, stored per-user)                     │
│  ──────────────────────────────────────────                     │
│                                                                  │
│  user_1: role_label="viewer"                                    │
│          permissions=[monitors:read, alerts:read]               │
│          (matches viewer template)                               │
│                                                                  │
│  user_2: role_label="custom"                                    │
│          base_role="editor"                                      │
│          permissions=[monitors:read, monitors:write,            │
│                       alerts:*, users:read]                     │
│          (editor + users:read = custom)                         │
│                                                                  │
│  user_3: role_label="custom"                                    │
│          base_role="viewer"                                      │
│          permissions=[monitors:read, alerts:read, billing:read] │
│          (viewer + billing:read = custom)                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Config File Format

### YAML Format

```yaml
# permissions.yaml
version: 1

permission_groups:
  - key: monitors
    name: Monitors
    description: Monitor resources
    permissions:
      - key: monitors:read
        name: View monitors
      - key: monitors:write
        name: Create & edit monitors
      - key: monitors:delete
        name: Delete monitors

  - key: alerts
    name: Alerts
    description: Alert management
    permissions:
      - key: alerts:read
        name: View alerts
      - key: alerts:write
        name: Create & manage alerts
      - key: alerts:delete
        name: Delete alerts

  - key: users
    name: Users
    description: User management
    permissions:
      - key: users:read
        name: View users
      - key: users:write
        name: Invite & edit users
      - key: users:delete
        name: Remove users

  - key: billing
    name: Billing
    description: Billing & subscription
    permissions:
      - key: billing:read
        name: View invoices & plans
      - key: billing:write
        name: Manage subscription

role_templates:
  - key: viewer
    name: Viewer
    description: Read-only access
    permissions:
      - monitors:read
      - alerts:read

  - key: editor
    name: Editor
    description: Can create and modify
    permissions:
      - monitors:read
      - monitors:write
      - alerts:read
      - alerts:write

  - key: admin
    name: Admin
    description: Full access except billing
    permissions:
      - monitors:*
      - alerts:*
      - users:read
      - users:write

  - key: owner
    name: Owner
    description: Full access
    permissions:
      - "*"
```

### JSON Format

```json
{
  "version": 1,
  "permission_groups": [
    {
      "key": "monitors",
      "name": "Monitors",
      "description": "Monitor resources",
      "permissions": [
        { "key": "monitors:read", "name": "View monitors" },
        { "key": "monitors:write", "name": "Create & edit monitors" },
        { "key": "monitors:delete", "name": "Delete monitors" }
      ]
    }
  ],
  "role_templates": [
    {
      "key": "viewer",
      "name": "Viewer",
      "description": "Read-only access",
      "permissions": ["monitors:read", "alerts:read"]
    }
  ]
}
```

## Startup Sync

When application starts, role template changes are synced to users.

### Sync Logic

```
┌─────────────────────────────────────────────────────────────────┐
│                 Startup Config Sync Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Load config file (permissions.yaml)                          │
│                                                                  │
│  2. Load stored role templates from DB                           │
│                                                                  │
│  3. Compare each role template:                                  │
│                                                                  │
│     Config:  editor → [monitors:*, alerts:*, users:read]        │
│     Stored:  editor → [monitors:read, monitors:write, alerts:*] │
│     Changed? YES                                                 │
│                                                                  │
│  4. Find users to update:                                        │
│     WHERE role_label = 'editor' (not 'custom')                  │
│                                                                  │
│  5. Update those users:                                          │
│     - Set permissions = new template permissions                 │
│     - Bump permission_version                                    │
│     - Keep role_label = 'editor'                                │
│                                                                  │
│  6. Update stored role templates in DB                           │
│                                                                  │
│  7. Log changes in audit table                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Sync Rules

| role_label | base_role | Template Changed? | Action |
|------------|-----------|-------------------|--------|
| editor | editor | Yes | ✅ Update permissions |
| editor | editor | No | Skip |
| custom | editor | Yes | ❌ Skip (customized) |
| custom | viewer | No | Skip |

## Permission Resolution

```go
// At request time, resolve effective permissions
func (r *Resolver) ResolvePermissions(userID string) ([]string, error) {
    // 1. Fetch user's permissions from store
    user, err := r.store.GetUserPermissions(ctx, userID)
    if err != nil {
        return nil, err
    }
    
    // 2. Expand wildcards for checking
    // (stored as-is, expanded at check time)
    return user.Permissions, nil
}

// Check if user has a specific permission
func (r *Resolver) HasPermission(permissions []string, required string) bool {
    for _, perm := range permissions {
        if r.matches(perm, required) {
            return true
        }
    }
    return false
}

// Wildcard matching
func (r *Resolver) matches(held, required string) bool {
    // Exact match
    if held == required {
        return true
    }
    
    // Superuser
    if held == "*" {
        return true
    }
    
    // Wildcard in resource (e.g., "monitors:*" matches "monitors:read")
    if strings.HasSuffix(held, ":*") {
        prefix := strings.TrimSuffix(held, "*")
        if strings.HasPrefix(required, prefix) {
            return true
        }
    }
    
    // Wildcard in action (e.g., "*:read" matches "monitors:read")
    if strings.HasPrefix(held, "*:") {
        suffix := strings.TrimPrefix(held, "*")
        if strings.HasSuffix(required, suffix) {
            return true
        }
    }
    
    return false
}
```

## API for Permission Management

### Assign Role Template

```go
// Copies template permissions to user
err := auth.AssignRole(ctx, userID, "editor")

// Result:
// - permissions = [monitors:read, monitors:write, alerts:read, alerts:write]
// - role_label = "editor"
// - base_role = "editor"
// - permission_version++
```

### Add Permissions

```go
// Add specific permissions to user
err := auth.AddPermissions(ctx, userID, []string{"users:read", "billing:read"})

// Result:
// - permissions = [...existing..., users:read, billing:read]
// - role_label = "custom" (no longer matches template)
// - permission_version++
```

### Remove Permissions

```go
// Remove specific permissions from user
err := auth.RemovePermissions(ctx, userID, []string{"monitors:write"})

// Result:
// - permissions = [...without monitors:write...]
// - role_label = auto-detected (might still match a template)
// - permission_version++
```

### Set Exact Permissions

```go
// Replace all permissions
err := auth.SetPermissions(ctx, userID, []string{
    "monitors:read",
    "alerts:read",
    "billing:read",
})

// Result:
// - permissions = exactly as specified
// - role_label = auto-detected
// - permission_version++
```

### Get User Permissions

```go
// For displaying in UI
perms, err := auth.GetUserPermissions(ctx, userID)

// Returns:
// {
//     UserID: "user_123",
//     RoleLabel: "custom",
//     BaseRole: "editor",
//     Permissions: ["monitors:read", "alerts:*", "users:read"],
//     PermissionVersion: 5,
// }
```

### Get Available Permissions (for UI)

```go
// Get all permission groups for rendering checkboxes
groups := auth.GetPermissionGroups()

// Returns structured data for UI
```

### Reset to Role Template

```go
// Force user back to their base role's current permissions
err := auth.ResetToRoleTemplate(ctx, userID)

// Result:
// - permissions = current template permissions
// - role_label = base_role
// - permission_version++
```

## Middleware Authorization

```go
// Require specific permission
router.Post("/monitors", 
    auth.RequirePermission("monitors:write"),
    createMonitorHandler,
)

// Require any of these permissions
router.Get("/reports",
    auth.RequireAnyPermission("reports:read", "admin:*"),
    reportsHandler,
)

// Require all permissions
router.Delete("/users/:id",
    auth.RequirePermissions("users:read", "users:delete"),
    deleteUserHandler,
)

// Check in handler
func handler(w http.ResponseWriter, r *http.Request) {
    claims := goauth.ClaimsFromContext[MyClaims](r.Context())
    
    if auth.HasPermission(claims.Permissions, "monitors:delete") {
        // Show delete button
    }
}
```
