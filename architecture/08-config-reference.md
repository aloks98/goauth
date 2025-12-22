# Configuration Reference

## Builder Options

### Required Options

#### WithSecret

Sets the secret key for JWT signing (HS256).

```go
goauth.WithSecret("your-256-bit-secret-key-here")
```

**Note:** Use a strong, random secret of at least 32 bytes.

#### WithStore

Sets the data store (required for stateful operations).

```go
// PostgreSQL
goauth.WithStore(sql.Postgres("postgres://user:pass@localhost/db"))

// MySQL
goauth.WithStore(sql.MySQL("user:pass@tcp(localhost:3306)/db"))

// SQLite
goauth.WithStore(sql.SQLite("./data/auth.db"))

// Redis
goauth.WithStore(redis.New("localhost:6379", "", 0))

// Memory (testing only)
goauth.WithStore(memory.New())
```

### RBAC Configuration (Optional)

RBAC is optional. If not configured, GoAuth runs in simple mode (auth only).

#### WithRBACFromFile

Loads RBAC configuration from a YAML or JSON file. **Enables RBAC mode.**

```go
goauth.WithRBACFromFile("./config/permissions.yaml")
goauth.WithRBACFromFile("./config/permissions.json")
```

#### WithRBACFromBytes

Loads RBAC configuration from embedded bytes. **Enables RBAC mode.**

```go
//go:embed config/permissions.yaml
var permissionsConfig []byte

goauth.WithRBACFromBytes(permissionsConfig)
```

#### WithRBACFromEnv

Loads RBAC config path from environment variable. **Enables RBAC mode.**

```go
// Reads GOAUTH_RBAC_CONFIG environment variable
goauth.WithRBACFromEnv()
```

### Token Configuration

#### WithAccessTokenTTL

Sets access token expiration time.

```go
goauth.WithAccessTokenTTL(15 * time.Minute)  // Default: 15 minutes
```

#### WithRefreshTokenTTL

Sets refresh token expiration time.

```go
goauth.WithRefreshTokenTTL(7 * 24 * time.Hour)  // Default: 7 days
```

#### WithSigningMethod

Sets JWT signing method.

```go
goauth.WithSigningMethod(goauth.HS256)  // Default
goauth.WithSigningMethod(goauth.HS384)
goauth.WithSigningMethod(goauth.HS512)
goauth.WithSigningMethod(goauth.RS256)
goauth.WithSigningMethod(goauth.RS384)
goauth.WithSigningMethod(goauth.RS512)
```

#### WithKeyPair (for RS* methods)

Sets RSA key pair for RS* signing methods.

```go
goauth.WithKeyPair(privateKey, publicKey)
```

### Store Configuration

#### WithTablePrefix

Sets prefix for database table names.

```go
goauth.WithTablePrefix("myapp_")
// Tables: myapp_auth_refresh_tokens, myapp_auth_user_permissions, etc.
```

#### WithAutoMigrate

Enables automatic table creation on startup.

```go
goauth.WithAutoMigrate(true)  // Default: false
```

#### WithCleanupInterval

Sets interval for background cleanup of expired tokens.

```go
goauth.WithCleanupInterval(1 * time.Hour)  // Default: 1 hour
```

### Permission Configuration

#### WithPermissionVersionCheck

Enables checking permission version on each request.

```go
goauth.WithPermissionVersionCheck(true)  // Default: true
```

#### WithPermissionCacheTTL

Sets cache TTL for permission lookups.

```go
goauth.WithPermissionCacheTTL(30 * time.Second)  // Default: 30 seconds
```

#### WithRoleSyncOnStartup

Enables syncing role templates to users on startup.

```go
goauth.WithRoleSyncOnStartup(true)  // Default: true
```

### Password Configuration

#### WithPasswordHasher

Sets the password hashing algorithm.

```go
// Argon2id (default, recommended)
goauth.WithPasswordHasher(password.NewArgon2(password.Argon2Config{
    Memory:      64 * 1024,  // 64 MB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
}))

// Bcrypt
goauth.WithPasswordHasher(password.NewBcrypt(password.BcryptConfig{
    Cost: 12,
}))
```

### API Key Configuration

#### WithAPIKeyPrefix

Sets default prefix for generated API keys.

```go
goauth.WithAPIKeyPrefix("sk")  // Default: "sk"
// Keys: sk_abc123...
```

#### WithAPIKeyLength

Sets the random byte length for API keys.

```go
goauth.WithAPIKeyLength(32)  // Default: 32 bytes
```

### Rate Limiting (Optional)

#### WithRateLimiter

Enables rate limiting for authentication endpoints.

```go
goauth.WithRateLimiter(ratelimit.Config{
    Login: ratelimit.Rule{
        Requests: 5,
        Window:   15 * time.Minute,
        KeyBy:    ratelimit.KeyByEmail,
    },
    Register: ratelimit.Rule{
        Requests: 3,
        Window:   1 * time.Hour,
        KeyBy:    ratelimit.KeyByIP,
    },
    Refresh: ratelimit.Rule{
        Requests: 10,
        Window:   1 * time.Minute,
        KeyBy:    ratelimit.KeyByUserID,
    },
})
```

---

## RBAC Config File Schema

### YAML Schema

```yaml
# Version of the config schema
version: 1

# Permission groups (for UI organization)
permission_groups:
  - key: string          # Unique identifier (required)
    name: string         # Display name (required)
    description: string  # Description (optional)
    permissions:         # List of permissions
      - key: string      # Permission key, e.g., "monitors:read" (required)
        name: string     # Display name (required)
        description: string  # Description (optional)

# Role templates (presets)
role_templates:
  - key: string          # Unique identifier (required)
    name: string         # Display name (required)
    description: string  # Description (optional)
    permissions:         # List of permission keys
      - string           # e.g., "monitors:read", "monitors:*", "*"
```

### Config Validation Rules

On startup, the config is validated:

| Rule | Error |
|------|-------|
| Version must be 1 | `ErrConfigVersionUnsupported` |
| Permission keys must be unique | `ErrDuplicatePermission` |
| Role keys must be unique | `ErrDuplicateRole` |
| Role permissions must reference defined permissions (or wildcards) | `ErrRolePermissionNotFound` |
| Permission keys cannot be empty | `ErrEmptyPermissionKey` |
| Permission format must be `resource:action` or wildcard | `ErrInvalidPermissionFormat` |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GOAUTH_RBAC_CONFIG` | Path to RBAC config file (for `WithRBACFromEnv`) | - |
| `GOAUTH_SECRET` | JWT secret (alternative to `WithSecret`) | - |
| `GOAUTH_LOG_LEVEL` | Log level (debug, info, warn, error) | info |

---

## Complete Examples

### Simple Mode (No RBAC)

For applications that just need authentication:

```go
package main

import (
    "log"
    "time"
    
    "github.com/yourusername/goauth"
    "github.com/yourusername/goauth/store/sql"
)

type MyClaims struct {
    goauth.StandardClaims
    Role     string `json:"role"`      // Simple role field
    TenantID string `json:"tenant_id"`
}

func main() {
    auth, err := goauth.New[MyClaims](
        // Required
        goauth.WithSecret("your-very-secure-256-bit-secret-key"),
        goauth.WithStore(sql.Postgres("postgres://user:pass@localhost/myapp")),
        
        // Token settings
        goauth.WithAccessTokenTTL(15 * time.Minute),
        goauth.WithRefreshTokenTTL(7 * 24 * time.Hour),
        
        // Store settings
        goauth.WithTablePrefix("myapp_"),
        goauth.WithAutoMigrate(true),
        
        // No RBAC - simple auth mode
    )
    if err != nil {
        log.Fatalf("Failed to initialize auth: %v", err)
    }
    defer auth.Close()
    
    // Generate tokens with custom claims
    tokens, _ := auth.GenerateTokenPair(ctx, user.ID, MyClaims{
        Role:     user.Role,
        TenantID: user.TenantID,
    })
    
    // Check role in handlers
    claims := goauth.ClaimsFromContext[MyClaims](r.Context())
    if claims.Role != "admin" {
        // Forbidden
    }
}
```

### Full Mode (With RBAC)

For applications that need user-level permissions:

```go
package main

import (
    "log"
    "time"
    
    "github.com/yourusername/goauth"
    "github.com/yourusername/goauth/password"
    "github.com/yourusername/goauth/ratelimit"
    "github.com/yourusername/goauth/store/sql"
)

type MyClaims struct {
    goauth.StandardClaims
    TenantID string `json:"tenant_id"`
    OrgSlug  string `json:"org_slug"`
}

func main() {
    auth, err := goauth.New[MyClaims](
        // Required
        goauth.WithSecret("your-very-secure-256-bit-secret-key"),
        goauth.WithStore(sql.Postgres("postgres://user:pass@localhost/myapp")),
        goauth.WithRBACFromFile("./config/permissions.yaml"),  // ← Enables RBAC
        
        // Token settings
        goauth.WithAccessTokenTTL(15 * time.Minute),
        goauth.WithRefreshTokenTTL(7 * 24 * time.Hour),
        
        // Store settings
        goauth.WithTablePrefix("myapp_"),
        goauth.WithAutoMigrate(true),
        goauth.WithCleanupInterval(1 * time.Hour),
        
        // Permission settings (only relevant with RBAC)
        goauth.WithPermissionVersionCheck(true),
        goauth.WithPermissionCacheTTL(30 * time.Second),
        goauth.WithRoleSyncOnStartup(true),
        
        // Password settings
        goauth.WithPasswordHasher(password.NewArgon2(password.DefaultArgon2Config)),
        
        // API key settings
        goauth.WithAPIKeyPrefix("sk_live"),
        goauth.WithAPIKeyLength(32),
        
        // Rate limiting
        goauth.WithRateLimiter(ratelimit.Config{
            Login: ratelimit.Rule{
                Requests: 5,
                Window:   15 * time.Minute,
                KeyBy:    ratelimit.KeyByEmail,
            },
        }),
    )
    if err != nil {
        log.Fatalf("Failed to initialize auth: %v", err)
    }
    defer auth.Close()
    
    // Full RBAC features available
    auth.AssignRole(ctx, userID, "editor")
    auth.AddPermissions(ctx, userID, []string{"billing:read"})
    
    // Use permission middleware
    mw := auth.Middleware()
    router.Handle("/api/monitors", 
        mw.RequirePermission("monitors:read")(handler))
}
```
