# Store Interface

## Overview

The store interface abstracts data persistence. GoAuth requires a store for stateful operations like refresh tokens, blacklisting, and user permissions.

## Store Interface

```go
type Store interface {
    // Lifecycle
    Close() error
    Ping(ctx context.Context) error
    
    // Migrations
    Migrate(ctx context.Context) error
    
    // Refresh Tokens
    SaveRefreshToken(ctx context.Context, token *RefreshToken) error
    GetRefreshToken(ctx context.Context, jti string) (*RefreshToken, error)
    RevokeRefreshToken(ctx context.Context, jti string, replacedBy string) error
    RevokeTokenFamily(ctx context.Context, familyID string) error
    RevokeAllUserRefreshTokens(ctx context.Context, userID string) error
    DeleteExpiredRefreshTokens(ctx context.Context) (int64, error)
    
    // Access Token Blacklist
    AddToBlacklist(ctx context.Context, jti string, expiresAt time.Time) error
    IsBlacklisted(ctx context.Context, jti string) (bool, error)
    DeleteExpiredBlacklistEntries(ctx context.Context) (int64, error)
    
    // User Permissions
    GetUserPermissions(ctx context.Context, userID string) (*UserPermissions, error)
    SaveUserPermissions(ctx context.Context, perms *UserPermissions) error
    UpdateUsersWithRole(ctx context.Context, roleLabel string, permissions []string) (int64, error)
    DeleteUserPermissions(ctx context.Context, userID string) error
    
    // Role Templates (for sync)
    GetRoleTemplates(ctx context.Context) (map[string]*StoredRoleTemplate, error)
    SaveRoleTemplate(ctx context.Context, template *StoredRoleTemplate) error
    
    // Role Sync Audit
    LogRoleSync(ctx context.Context, log *RoleSyncLog) error
    
    // API Keys
    SaveAPIKey(ctx context.Context, key *APIKey) error
    GetAPIKeyByPrefix(ctx context.Context, prefix string, keyHash string) (*APIKey, error)
    GetAPIKeysByUser(ctx context.Context, userID string) ([]*APIKey, error)
    RevokeAPIKey(ctx context.Context, id string) error
    UpdateAPIKeyLastUsed(ctx context.Context, id string) error
    DeleteExpiredAPIKeys(ctx context.Context) (int64, error)
}
```

## Data Models

### RefreshToken

```go
type RefreshToken struct {
    ID          string    `db:"id"`
    UserID      string    `db:"user_id"`
    FamilyID    string    `db:"family_id"`
    TokenHash   string    `db:"token_hash"`
    IssuedAt    time.Time `db:"issued_at"`
    ExpiresAt   time.Time `db:"expires_at"`
    RevokedAt   *time.Time `db:"revoked_at"`
    ReplacedBy  *string   `db:"replaced_by"`
}
```

### UserPermissions

```go
type UserPermissions struct {
    UserID            string    `db:"user_id"`
    RoleLabel         string    `db:"role_label"`
    BaseRole          string    `db:"base_role"`
    Permissions       []string  `db:"permissions"`
    PermissionVersion int       `db:"permission_version"`
    UpdatedAt         time.Time `db:"updated_at"`
    UpdatedBy         *string   `db:"updated_by"`
}
```

### StoredRoleTemplate

```go
type StoredRoleTemplate struct {
    RoleKey         string    `db:"role_key"`
    Name            string    `db:"name"`
    Description     string    `db:"description"`
    Permissions     []string  `db:"permissions"`
    PermissionsHash string    `db:"permissions_hash"`
    UpdatedAt       time.Time `db:"updated_at"`
}
```

### APIKey

```go
type APIKey struct {
    ID          string     `db:"id"`
    UserID      string     `db:"user_id"`
    Prefix      string     `db:"prefix"`
    KeyHash     string     `db:"key_hash"`
    Name        string     `db:"name"`
    Scopes      []string   `db:"scopes"`
    LastUsedAt  *time.Time `db:"last_used_at"`
    ExpiresAt   *time.Time `db:"expires_at"`
    CreatedAt   time.Time  `db:"created_at"`
    RevokedAt   *time.Time `db:"revoked_at"`
}
```

### RoleSyncLog

```go
type RoleSyncLog struct {
    ID             string    `db:"id"`
    RoleKey        string    `db:"role_key"`
    OldPermissions []string  `db:"old_permissions"`
    NewPermissions []string  `db:"new_permissions"`
    UsersAffected  int64     `db:"users_affected"`
    SyncedAt       time.Time `db:"synced_at"`
}
```

## Store Implementations

### SQL Store (PostgreSQL, MySQL, SQLite)

```go
// PostgreSQL
store, err := sql.NewPostgres(sql.Config{
    DSN:         "postgres://user:pass@localhost/db",
    TablePrefix: "myapp_",
    MaxConns:    10,
})

// MySQL
store, err := sql.NewMySQL(sql.Config{
    DSN:         "user:pass@tcp(localhost:3306)/db",
    TablePrefix: "myapp_",
})

// SQLite
store, err := sql.NewSQLite(sql.Config{
    Path:        "./data/auth.db",
    TablePrefix: "",
})
```

### Redis Store

```go
store, err := redis.New(redis.Config{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
    Prefix:   "goauth:",
})
```

## Configuration Options

```go
goauth.WithStore(store)                    // Required
goauth.WithTablePrefix("myapp_")           // Table name prefix
goauth.WithAutoMigrate(true)               // Auto-create tables
goauth.WithCleanupInterval(1 * time.Hour)  // Background cleanup interval
```

## Table Prefix

All SQL tables are prefixed with the configured prefix:

| Default Name | With Prefix `myapp_` |
|--------------|----------------------|
| `auth_refresh_tokens` | `myapp_auth_refresh_tokens` |
| `auth_token_blacklist` | `myapp_auth_token_blacklist` |
| `auth_user_permissions` | `myapp_auth_user_permissions` |
| `auth_role_templates` | `myapp_auth_role_templates` |
| `auth_role_sync_log` | `myapp_auth_role_sync_log` |
| `auth_api_keys` | `myapp_auth_api_keys` |

## Store Selection Guide

| Store | Use Case |
|-------|----------|
| PostgreSQL | Production, full features, best performance |
| MySQL | Production, if already using MySQL |
| SQLite | Single-instance apps, embedded, development |
| Redis | When you need fastest blacklist checks |
| Memory | Unit testing only |

## Combining Stores

For optimal performance, you can use different stores for different purposes:

```go
// Example: SQL for persistence, Redis for caching
// (Future enhancement - not in initial release)
```
