# GoAuth API Reference

Complete API documentation for the GoAuth library.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Types](#core-types)
- [Configuration](#configuration)
- [Token Methods](#token-methods)
- [API Key Methods](#api-key-methods)
- [RBAC Methods](#rbac-methods)
- [Middleware](#middleware)
- [Store Interface](#store-interface)
- [Error Handling](#error-handling)

---

## Installation

```bash
go get github.com/aloks98/goauth
```

---

## Quick Start

```go
import (
    "github.com/aloks98/goauth"
    "github.com/aloks98/goauth/store/memory"
)

// Define your custom claims (must embed StandardClaims)
type MyClaims struct {
    goauth.StandardClaims
    Email string `json:"email"`
}

// Create auth instance
auth, err := goauth.New[*MyClaims](
    goauth.WithSecret("your-256-bit-secret-key-here"),
    goauth.WithStore(memory.New()),
)
if err != nil {
    log.Fatal(err)
}
defer auth.Close()
```

---

## Core Types

### Auth[T Claims]

The main entry point for all GoAuth functionality. `T` is your custom claims type.

```go
type Auth[T Claims] struct {
    // unexported fields
}
```

### StandardClaims

Base claims that must be embedded in your custom claims type.

```go
type StandardClaims struct {
    UserID            string `json:"sub"`      // User identifier
    JTI               string `json:"jti"`      // JWT ID (unique token identifier)
    IssuedAt          int64  `json:"iat"`      // Unix timestamp
    ExpiresAt         int64  `json:"exp"`      // Unix timestamp
    PermissionVersion int    `json:"pv"`       // For RBAC version tracking
}
```

**Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `GetUserID()` | `string` | Returns the user ID |
| `GetJTI()` | `string` | Returns the JWT ID |
| `GetIssuedAt()` | `time.Time` | Returns issued at time |
| `GetExpiresAt()` | `time.Time` | Returns expiration time |
| `IsExpired()` | `bool` | Returns true if token has expired |
| `TimeUntilExpiry()` | `time.Duration` | Returns duration until expiry |

### token.Pair

Returned when generating or refreshing tokens.

```go
type Pair struct {
    AccessToken  string    `json:"access_token"`   // JWT access token
    RefreshToken string    `json:"refresh_token"`  // Opaque refresh token
    TokenType    string    `json:"token_type"`     // Always "Bearer"
    ExpiresIn    int64     `json:"expires_in"`     // Seconds until expiry
    ExpiresAt    time.Time `json:"expires_at"`     // Absolute expiry time
}
```

### token.Claims

Claims extracted from a validated access token.

```go
type Claims struct {
    UserID            string         `json:"sub"`
    JTI               string         `json:"jti"`
    PermissionVersion int            `json:"pv,omitempty"`
    Custom            map[string]any `json:"custom,omitempty"`
    jwt.RegisteredClaims
}
```

---

## Configuration

### Constructor

```go
func New[T Claims](opts ...Option) (*Auth[T], error)
```

Creates a new Auth instance. At minimum, `WithSecret` and `WithStore` must be provided.

**Parameters:**
- `opts`: Variadic configuration options

**Returns:**
- `*Auth[T]`: The configured auth instance
- `error`: Configuration or initialization error

### Configuration Options

| Option | Signature | Description | Default |
|--------|-----------|-------------|---------|
| `WithSecret` | `(secret string)` | HMAC signing secret (min 32 chars) | Required |
| `WithStore` | `(store.Store)` | Data store for tokens/permissions | Required |
| `WithAccessTokenTTL` | `(time.Duration)` | Access token lifetime | 15 minutes |
| `WithRefreshTokenTTL` | `(time.Duration)` | Refresh token lifetime | 7 days |
| `WithSigningMethod` | `(SigningMethod)` | JWT signing algorithm | HS256 |
| `WithKeyPair` | `(privateKey, publicKey any)` | RSA keys for RS* methods | - |
| `WithRBACFromFile` | `(path string)` | Load RBAC config from YAML/JSON | - |
| `WithRBACFromBytes` | `(data []byte)` | Load RBAC config from bytes | - |
| `WithAutoMigrate` | `(bool)` | Auto-create database tables | false |
| `WithCleanupInterval` | `(time.Duration)` | Expired token cleanup interval | 1 hour |
| `WithPermissionVersionCheck` | `(bool)` | Reject tokens with old permission versions | true |
| `WithAPIKeyPrefix` | `(string)` | Prefix for generated API keys | "sk" |
| `WithAPIKeyLength` | `(int)` | Length of random portion of API keys | 32 |
| `WithTablePrefix` | `(string)` | Prefix for database table names | "auth_" |

### Signing Methods

```go
const (
    SigningMethodHS256 SigningMethod = "HS256"  // HMAC-SHA256 (symmetric)
    SigningMethodHS384 SigningMethod = "HS384"  // HMAC-SHA384 (symmetric)
    SigningMethodHS512 SigningMethod = "HS512"  // HMAC-SHA512 (symmetric)
    SigningMethodRS256 SigningMethod = "RS256"  // RSA-SHA256 (asymmetric)
    SigningMethodRS384 SigningMethod = "RS384"  // RSA-SHA384 (asymmetric)
    SigningMethodRS512 SigningMethod = "RS512"  // RSA-SHA512 (asymmetric)
)
```

### Example Configuration

```go
auth, err := goauth.New[*MyClaims](
    goauth.WithSecret("your-256-bit-secret-key-here"),
    goauth.WithStore(store),
    goauth.WithAccessTokenTTL(30 * time.Minute),
    goauth.WithRefreshTokenTTL(14 * 24 * time.Hour),
    goauth.WithRBACFromFile("./permissions.yaml"),
    goauth.WithAutoMigrate(true),
    goauth.WithCleanupInterval(30 * time.Minute),
)
```

---

## Token Methods

### GenerateTokenPair

Generates a new access/refresh token pair for a user.

```go
func (a *Auth[T]) GenerateTokenPair(
    ctx context.Context,
    userID string,
    customClaims map[string]any,
) (*token.Pair, error)
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `ctx` | `context.Context` | Request context |
| `userID` | `string` | Unique user identifier |
| `customClaims` | `map[string]any` | Additional claims to include in JWT |

**Returns:**
| Type | Description |
|------|-------------|
| `*token.Pair` | Access and refresh token pair |
| `error` | Error if generation fails |

**Example:**
```go
tokens, err := auth.GenerateTokenPair(ctx, "user-123", map[string]any{
    "email": "user@example.com",
    "role":  "admin",
})
if err != nil {
    return err
}
// tokens.AccessToken, tokens.RefreshToken
```

---

### ValidateAccessToken

Validates an access token and returns its claims.

```go
func (a *Auth[T]) ValidateAccessToken(
    ctx context.Context,
    tokenString string,
) (*token.Claims, error)
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `ctx` | `context.Context` | Request context |
| `tokenString` | `string` | The JWT access token |

**Returns:**
| Type | Description |
|------|-------------|
| `*token.Claims` | Validated claims from the token |
| `error` | Validation error (expired, blacklisted, etc.) |

**Possible Errors:**
- `ErrTokenExpired` - Token has expired
- `ErrTokenMalformed` - Token is malformed
- `ErrTokenInvalidSig` - Invalid signature
- `ErrTokenBlacklisted` - Token has been revoked
- `ErrPermissionsChanged` - User permissions have changed

**Example:**
```go
claims, err := auth.ValidateAccessToken(ctx, tokenString)
if err != nil {
    if errors.Is(err, goauth.ErrTokenExpired) {
        // Handle expired token - try refresh
    }
    return err
}
userID := claims.UserID
```

---

### RefreshTokens

Validates a refresh token and returns a new token pair (with rotation).

```go
func (a *Auth[T]) RefreshTokens(
    ctx context.Context,
    refreshToken string,
) (*token.Pair, error)
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `ctx` | `context.Context` | Request context |
| `refreshToken` | `string` | The refresh token |

**Returns:**
| Type | Description |
|------|-------------|
| `*token.Pair` | New access and refresh token pair |
| `error` | Validation error |

**Possible Errors:**
- `ErrRefreshTokenExpired` - Refresh token has expired
- `ErrRefreshTokenInvalid` - Refresh token is invalid
- `ErrRefreshTokenReused` - Token was already used (theft detected!)
- `ErrTokenFamilyRevoked` - Entire token family was revoked

**Example:**
```go
newTokens, err := auth.RefreshTokens(ctx, refreshToken)
if err != nil {
    if errors.Is(err, goauth.ErrRefreshTokenReused) {
        // Possible token theft - user should re-authenticate
        auth.RevokeAllUserTokens(ctx, userID)
    }
    return err
}
```

---

### RevokeAccessToken

Adds an access token to the blacklist, preventing further use.

```go
func (a *Auth[T]) RevokeAccessToken(
    ctx context.Context,
    tokenString string,
) error
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `ctx` | `context.Context` | Request context |
| `tokenString` | `string` | The access token to revoke |

**Returns:**
| Type | Description |
|------|-------------|
| `error` | Error if revocation fails |

**Example:**
```go
// Logout - revoke the current access token
err := auth.RevokeAccessToken(ctx, accessToken)
```

---

### RevokeRefreshToken

Revokes a specific refresh token by its JTI.

```go
func (a *Auth[T]) RevokeRefreshToken(
    ctx context.Context,
    jti string,
) error
```

---

### RevokeTokenFamily

Revokes all tokens in a token family (useful when theft is detected).

```go
func (a *Auth[T]) RevokeTokenFamily(
    ctx context.Context,
    familyID string,
) error
```

---

### RevokeAllUserTokens

Revokes all refresh tokens for a user (logout from all devices).

```go
func (a *Auth[T]) RevokeAllUserTokens(
    ctx context.Context,
    userID string,
) error
```

**Example:**
```go
// Logout from all devices
err := auth.RevokeAllUserTokens(ctx, userID)
```

---

## API Key Methods

### CreateAPIKey

Generates a new API key for a user. The raw key is only returned once.

```go
func (a *Auth[T]) CreateAPIKey(
    ctx context.Context,
    userID string,
    opts *apikey.CreateKeyOptions,
) (*apikey.CreateKeyResult, error)
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `ctx` | `context.Context` | Request context |
| `userID` | `string` | User who owns the key |
| `opts` | `*apikey.CreateKeyOptions` | Key options (name, scopes, expiry) |

**CreateKeyOptions:**
```go
type CreateKeyOptions struct {
    Name      string      // Human-readable name
    Scopes    []string    // Limit to specific permissions (nil = all)
    ExpiresAt *time.Time  // Custom expiration time
    TTL       time.Duration // Alternative: expire after duration
}
```

**Returns:**
```go
type CreateKeyResult struct {
    ID        string      // Unique identifier for management
    RawKey    string      // The full API key (SHOW ONCE!)
    Prefix    string      // Key prefix (e.g., "sk_live")
    Hint      string      // Last few characters for identification
    Name      string      // Human-readable name
    ExpiresAt *time.Time  // When the key expires
}
```

**Example:**
```go
key, err := auth.CreateAPIKey(ctx, userID, &apikey.CreateKeyOptions{
    Name:   "Production API Key",
    Scopes: []string{"read", "write"},
    TTL:    30 * 24 * time.Hour, // 30 days
})
if err != nil {
    return err
}
// IMPORTANT: key.RawKey is only available now!
fmt.Printf("API Key: %s (save this, it won't be shown again!)\n", key.RawKey)
```

---

### ValidateAPIKey

Validates an API key and returns its metadata.

```go
func (a *Auth[T]) ValidateAPIKey(
    ctx context.Context,
    rawKey string,
) (*apikey.ValidateResult, error)
```

**Returns:**
```go
type ValidateResult struct {
    Key    *store.APIKey  // Full key metadata
    UserID string         // Owner's user ID
}
```

**Possible Errors:**
- `ErrAPIKeyInvalid` - Key is invalid or not found
- `ErrAPIKeyExpired` - Key has expired
- `ErrAPIKeyRevoked` - Key has been revoked

**Example:**
```go
result, err := auth.ValidateAPIKey(ctx, rawKey)
if err != nil {
    return err
}
userID := result.UserID
```

---

### ValidateAPIKeyWithScope

Validates an API key and checks for a required scope.

```go
func (a *Auth[T]) ValidateAPIKeyWithScope(
    ctx context.Context,
    rawKey string,
    requiredScope string,
) (*apikey.ValidateResult, error)
```

**Example:**
```go
result, err := auth.ValidateAPIKeyWithScope(ctx, rawKey, "write")
if err != nil {
    // Key invalid or doesn't have "write" scope
    return err
}
```

---

### RevokeAPIKey

Revokes an API key by its ID.

```go
func (a *Auth[T]) RevokeAPIKey(
    ctx context.Context,
    id string,
) error
```

---

### ListAPIKeys

Returns all API keys for a user (without the raw key values).

```go
func (a *Auth[T]) ListAPIKeys(
    ctx context.Context,
    userID string,
) ([]*store.APIKey, error)
```

**store.APIKey fields:**
```go
type APIKey struct {
    ID         string      // Unique identifier
    UserID     string      // Owner
    Name       string      // Human-readable name
    Prefix     string      // Key prefix
    Hint       string      // Last few chars
    Scopes     []string    // Allowed scopes
    CreatedAt  time.Time   // Creation time
    ExpiresAt  *time.Time  // Expiration (nil = never)
    LastUsedAt *time.Time  // Last usage
    RevokedAt  *time.Time  // Revocation time (nil = active)
}
```

---

## RBAC Methods

> **Note:** All RBAC methods return `ErrRBACNotEnabled` if RBAC is not configured.

### AssignRole

Assigns a role template to a user, copying its permissions.

```go
func (a *Auth[T]) AssignRole(
    ctx context.Context,
    userID string,
    roleKey string,
) error
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `ctx` | `context.Context` | Request context |
| `userID` | `string` | User to assign role to |
| `roleKey` | `string` | Role template key (e.g., "admin", "editor") |

**Example:**
```go
err := auth.AssignRole(ctx, "user-123", "editor")
```

---

### HasPermission

Checks if a user has a specific permission.

```go
func (a *Auth[T]) HasPermission(
    ctx context.Context,
    userID string,
    permission string,
) (bool, error)
```

**Permission Format:**
- `resource:action` - e.g., "posts:read", "users:delete"
- `resource:*` - All actions on resource
- `*:action` - Action on all resources
- `*` - Superuser (all permissions)

**Example:**
```go
canEdit, err := auth.HasPermission(ctx, userID, "posts:update")
if err != nil {
    return err
}
if !canEdit {
    return errors.New("permission denied")
}
```

---

### HasAllPermissions

Checks if a user has ALL specified permissions.

```go
func (a *Auth[T]) HasAllPermissions(
    ctx context.Context,
    userID string,
    permissions []string,
) (bool, error)
```

**Example:**
```go
hasAll, err := auth.HasAllPermissions(ctx, userID, []string{
    "posts:read",
    "posts:update",
    "posts:delete",
})
```

---

### HasAnyPermission

Checks if a user has ANY of the specified permissions.

```go
func (a *Auth[T]) HasAnyPermission(
    ctx context.Context,
    userID string,
    permissions []string,
) (bool, error)
```

---

### RequirePermission

Returns an error if the user doesn't have the permission.

```go
func (a *Auth[T]) RequirePermission(
    ctx context.Context,
    userID string,
    permission string,
) error
```

**Returns:**
- `nil` if user has permission
- `ErrPermissionDenied` if user lacks permission

**Example:**
```go
if err := auth.RequirePermission(ctx, userID, "admin:access"); err != nil {
    return err // Permission denied
}
// User has admin access
```

---

### AddPermissions

Adds permissions to a user without changing their role.

```go
func (a *Auth[T]) AddPermissions(
    ctx context.Context,
    userID string,
    permissions []string,
) error
```

**Note:** This marks the user as "custom" role if they had a base role.

**Example:**
```go
err := auth.AddPermissions(ctx, userID, []string{
    "reports:read",
    "reports:export",
})
```

---

### RemovePermissions

Removes permissions from a user.

```go
func (a *Auth[T]) RemovePermissions(
    ctx context.Context,
    userID string,
    permissions []string,
) error
```

---

### SetPermissions

Directly sets a user's permissions (replaces all existing).

```go
func (a *Auth[T]) SetPermissions(
    ctx context.Context,
    userID string,
    permissions []string,
) error
```

---

### ResetToRole

Resets a user's permissions to match their base role template.

```go
func (a *Auth[T]) ResetToRole(
    ctx context.Context,
    userID string,
) error
```

---

### GetUserPermissions

Returns a user's complete permission record.

```go
func (a *Auth[T]) GetUserPermissions(
    ctx context.Context,
    userID string,
) (*store.UserPermissions, error)
```

**store.UserPermissions:**
```go
type UserPermissions struct {
    UserID            string    // User identifier
    RoleLabel         string    // Current role ("admin", "custom", etc.)
    BaseRole          string    // Original assigned role
    Permissions       []string  // List of permissions
    PermissionVersion int       // Version number
    UpdatedAt         time.Time // Last modification
}
```

---

### GetAllRoles

Returns all defined role templates.

```go
func (a *Auth[T]) GetAllRoles() []RoleTemplate
```

**RoleTemplate:**
```go
type RoleTemplate struct {
    Key         string   // Unique identifier
    Name        string   // Display name
    Description string   // Description
    Permissions []string // List of permissions
}
```

---

### GetAllPermissionGroups

Returns all defined permission groups.

```go
func (a *Auth[T]) GetAllPermissionGroups() []PermissionGroup
```

---

## Middleware

### Context Helpers

```go
import "github.com/aloks98/goauth/middleware"

// Store claims in context
ctx = middleware.SetClaims(ctx, claims)

// Retrieve claims from context
claims := middleware.GetClaims(ctx)

// Store user ID in context
ctx = middleware.SetUserID(ctx, userID)

// Retrieve user ID from context
userID := middleware.GetUserID(ctx)

// Store permissions in context
ctx = middleware.SetPermissions(ctx, permissions)

// Retrieve permissions from context
permissions := middleware.GetPermissions(ctx)
```

### Token Extractors

```go
// Extract from Authorization header (default)
extractor := middleware.ExtractFromHeader("Authorization", "Bearer")

// Extract from query parameter
extractor := middleware.ExtractFromQuery("token")

// Extract from cookie
extractor := middleware.ExtractFromCookie("access_token")

// Chain multiple extractors
extractor := middleware.ChainExtractors(
    middleware.ExtractFromHeader("Authorization", "Bearer"),
    middleware.ExtractFromCookie("access_token"),
)
```

### Creating Middleware

For framework-specific middleware, see:
- `middleware/gin` - Gin framework
- `middleware/echo` - Echo framework
- `middleware/fiber` - Fiber framework
- `middleware/chi` - Chi router

**Generic net/http Example:**
```go
import "github.com/aloks98/goauth/middleware"

// Implement TokenValidator interface
type adapter struct {
    auth *goauth.Auth[*MyClaims]
}

func (a *adapter) ValidateToken(ctx context.Context, token string) (any, error) {
    return a.auth.ValidateAccessToken(ctx, token)
}

func (a *adapter) ExtractUserID(claims any) string {
    if c, ok := claims.(*token.Claims); ok {
        return c.UserID
    }
    return ""
}

// Use middleware
authMW := middleware.Authenticate(&adapter{auth}, &adapter{auth}, nil)
http.Handle("/protected", authMW(myHandler))
```

---

## Store Interface

GoAuth requires a store implementation for persistence.

### Available Stores

**Memory (for testing):**
```go
import "github.com/aloks98/goauth/store/memory"

store := memory.New()
```

**PostgreSQL:**
```go
import "github.com/aloks98/goauth/store/sql"

store, err := sql.NewPostgres("postgres://user:pass@localhost/db?sslmode=disable")
```

**MySQL:**
```go
import "github.com/aloks98/goauth/store/sql"

store, err := sql.NewMySQL("user:pass@tcp(localhost:3306)/db")
```

### Store Interface

```go
type Store interface {
    // Lifecycle
    Close() error
    Ping(ctx context.Context) error
    Migrate(ctx context.Context) error

    // Refresh Tokens
    SaveRefreshToken(ctx context.Context, token *RefreshToken) error
    GetRefreshToken(ctx context.Context, jti string) (*RefreshToken, error)
    RevokeRefreshToken(ctx context.Context, jti string, replacedBy string) error
    RevokeTokenFamily(ctx context.Context, familyID string) error
    RevokeAllUserRefreshTokens(ctx context.Context, userID string) error
    DeleteExpiredRefreshTokens(ctx context.Context) (int64, error)

    // Blacklist
    AddToBlacklist(ctx context.Context, jti string, expiresAt int64) error
    IsBlacklisted(ctx context.Context, jti string) (bool, error)
    DeleteExpiredBlacklistEntries(ctx context.Context) (int64, error)

    // User Permissions (RBAC)
    GetUserPermissions(ctx context.Context, userID string) (*UserPermissions, error)
    SaveUserPermissions(ctx context.Context, perms *UserPermissions) error
    DeleteUserPermissions(ctx context.Context, userID string) error
    UpdateUsersWithRole(ctx context.Context, roleLabel string, perms []string, version int) (int64, error)

    // Role Templates
    GetRoleTemplates(ctx context.Context) (map[string]*StoredRoleTemplate, error)
    SaveRoleTemplate(ctx context.Context, template *StoredRoleTemplate) error

    // API Keys
    SaveAPIKey(ctx context.Context, key *APIKey) error
    GetAPIKeyByHash(ctx context.Context, prefix string, keyHash string) (*APIKey, error)
    GetAPIKeysByUser(ctx context.Context, userID string) ([]*APIKey, error)
    RevokeAPIKey(ctx context.Context, id string) error
    DeleteExpiredAPIKeys(ctx context.Context) (int64, error)
}
```

---

## Error Handling

### Error Types

```go
import "github.com/aloks98/goauth"

// Token errors
goauth.ErrTokenExpired       // Token has expired
goauth.ErrTokenNotYetValid   // Token not yet valid (future iat)
goauth.ErrTokenMalformed     // Token is malformed
goauth.ErrTokenInvalidSig    // Invalid signature
goauth.ErrTokenBlacklisted   // Token has been revoked
goauth.ErrPermissionsChanged // User permissions changed since token issued

// Refresh token errors
goauth.ErrRefreshTokenReused  // Token was already used (theft!)
goauth.ErrRefreshTokenExpired // Refresh token expired
goauth.ErrRefreshTokenInvalid // Refresh token invalid
goauth.ErrTokenFamilyRevoked  // Token family revoked

// API key errors
goauth.ErrAPIKeyInvalid // API key not found
goauth.ErrAPIKeyExpired // API key expired
goauth.ErrAPIKeyRevoked // API key revoked

// RBAC errors
goauth.ErrRBACNotEnabled     // RBAC not configured
goauth.ErrPermissionDenied   // User lacks permission

// Config/Store errors
goauth.ErrStoreRequired      // Store not provided
goauth.ErrConfigInvalid      // Invalid configuration
```

### Error Checking

```go
import "errors"

claims, err := auth.ValidateAccessToken(ctx, token)
if err != nil {
    switch {
    case errors.Is(err, goauth.ErrTokenExpired):
        // Token expired - try refresh
    case errors.Is(err, goauth.ErrTokenBlacklisted):
        // Token was revoked - re-authenticate
    case errors.Is(err, goauth.ErrPermissionsChanged):
        // Permissions changed - get new token
    default:
        // Other error
    }
}
```

### Helper Functions

```go
// Check if error is token-related
if goauth.IsTokenError(err) {
    // Handle token error
}

// Check if error is refresh token-related
if goauth.IsRefreshTokenError(err) {
    // Handle refresh token error
}

// Check if error is API key-related
if goauth.IsAPIKeyError(err) {
    // Handle API key error
}

// Check if error is configuration-related
if goauth.IsConfigError(err) {
    // Handle config error
}
```

---

## Utility Methods

### Ping

Verifies the store connection is alive.

```go
func (a *Auth[T]) Ping(ctx context.Context) error
```

### Close

Releases all resources and stops background workers.

```go
func (a *Auth[T]) Close() error
```

**Important:** Always call `Close()` when done, typically with `defer`:

```go
auth, err := goauth.New[*MyClaims](opts...)
if err != nil {
    log.Fatal(err)
}
defer auth.Close()
```

### IsRBACEnabled

Returns true if RBAC is configured.

```go
func (a *Auth[T]) IsRBACEnabled() bool
```

### Config

Returns the current configuration (read-only).

```go
func (a *Auth[T]) Config() *Config
```

### Store

Returns the underlying store.

```go
func (a *Auth[T]) Store() store.Store
```
