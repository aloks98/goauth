# API Reference

## RBAC Requirement Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Works in all modes |
| 🔐 | Requires RBAC enabled |

---

## Constructor

### New[T]

Creates a new GoAuth instance with the specified claims type.

```go
func New[T Claims](opts ...Option) (*Auth[T], error)
```

**Simple Mode (no RBAC):**
```go
auth, err := goauth.New[MyClaims](
    goauth.WithSecret("your-256-bit-secret"),
    goauth.WithStore(sql.Postgres("postgres://...")),
)
```

**Full Mode (with RBAC):**
```go
auth, err := goauth.New[MyClaims](
    goauth.WithSecret("your-256-bit-secret"),
    goauth.WithStore(sql.Postgres("postgres://...")),
    goauth.WithRBACFromFile("./config/permissions.yaml"),
)
```

---

## Token Operations ✅

All token operations work in both modes.

### GenerateTokenPair

Generates access and refresh tokens for a user.

```go
func (a *Auth[T]) GenerateTokenPair(ctx context.Context, userID string, customClaims T) (*TokenPair, error)
```

**Note:** In RBAC mode, includes `permission_version` in claims. In simple mode, this is omitted.

### ValidateToken

Validates an access token and returns claims.

```go
func (a *Auth[T]) ValidateToken(ctx context.Context, token string) (*T, error)
```

**Example:**
```go
claims, err := auth.ValidateToken(ctx, tokenString)
if err != nil {
    // Handle error (expired, invalid, blacklisted)
}
```

### RefreshTokens

Refreshes the token pair using a refresh token.

```go
func (a *Auth[T]) RefreshTokens(ctx context.Context, refreshToken string) (*TokenPair, error)
```

**Example:**
```go
newTokens, err := auth.RefreshTokens(ctx, oldRefreshToken)
```

### RevokeToken

Revokes an access token by adding it to the blacklist.

```go
func (a *Auth[T]) RevokeToken(ctx context.Context, jti string) error
```

### RevokeRefreshToken

Revokes a specific refresh token.

```go
func (a *Auth[T]) RevokeRefreshToken(ctx context.Context, jti string) error
```

### RevokeAllUserTokens

Revokes all tokens for a user (logout all devices).

```go
func (a *Auth[T]) RevokeAllUserTokens(ctx context.Context, userID string) error
```

---

## Password Operations ✅

Password operations work in both modes.

### HashPassword

Hashes a password using the configured hasher (Argon2id by default).

```go
func (a *Auth[T]) HashPassword(password string) (string, error)
```

**Example:**
```go
hash, err := auth.HashPassword("user-password")
// Store hash in your user database
```

### VerifyPassword

Verifies a password against a hash.

```go
func (a *Auth[T]) VerifyPassword(password, hash string) (bool, error)
```

**Example:**
```go
valid, err := auth.VerifyPassword(inputPassword, user.PasswordHash)
if !valid {
    // Invalid password
}
```

---

## API Key Operations ✅

API key operations work in both modes.

> **Note:** In simple mode (no RBAC), API key scopes are stored but not validated against user permissions.

### GenerateAPIKey

Generates a new API key for a user.

```go
func (a *Auth[T]) GenerateAPIKey(ctx context.Context, userID string, opts APIKeyOptions) (*GeneratedAPIKey, error)
```

**Example:**
```go
result, err := auth.GenerateAPIKey(ctx, userID, goauth.APIKeyOptions{
    Name:   "Production Key",
    Prefix: "sk_live",
    Scopes: []string{"monitors:read", "alerts:read"},
    ExpiresIn: 365 * 24 * time.Hour, // Optional
})

// result.Key = "sk_live_abc123..." (show to user once)
// result.ID = "key-uuid" (for management)
```

### ValidateAPIKey

Validates an API key.

```go
func (a *Auth[T]) ValidateAPIKey(ctx context.Context, key string) (*APIKeyInfo, error)
```

**Example:**
```go
info, err := auth.ValidateAPIKey(ctx, apiKey)
if err != nil {
    // Invalid, expired, or revoked
}
// info.UserID, info.Scopes available
```

### RevokeAPIKey

Revokes an API key.

```go
func (a *Auth[T]) RevokeAPIKey(ctx context.Context, keyID string) error
```

### GetUserAPIKeys

Lists all API keys for a user.

```go
func (a *Auth[T]) GetUserAPIKeys(ctx context.Context, userID string) ([]*APIKeyInfo, error)
```

---

## RBAC Operations 🔐

> **Note:** These methods require RBAC to be enabled via `WithRBACFromFile()` or `WithRBACFromBytes()`. They return `ErrRBACNotEnabled` if called without RBAC configuration.

### AssignRole

Assigns a role template to a user (copies template permissions).

```go
func (a *Auth[T]) AssignRole(ctx context.Context, userID string, role string) error
```

**Example:**
```go
err := auth.AssignRole(ctx, userID, "editor")
// User now has editor's permissions
// role_label = "editor"
```

### AddPermissions

Adds permissions to a user.

```go
func (a *Auth[T]) AddPermissions(ctx context.Context, userID string, permissions []string) error
```

**Example:**
```go
err := auth.AddPermissions(ctx, userID, []string{"users:read", "billing:read"})
// role_label becomes "custom"
```

### RemovePermissions

Removes permissions from a user.

```go
func (a *Auth[T]) RemovePermissions(ctx context.Context, userID string, permissions []string) error
```

### SetPermissions

Sets exact permissions for a user (replaces all).

```go
func (a *Auth[T]) SetPermissions(ctx context.Context, userID string, permissions []string) error
```

### GetUserPermissions

Gets a user's current permissions.

```go
func (a *Auth[T]) GetUserPermissions(ctx context.Context, userID string) (*UserPermissions, error)
```

**Example:**
```go
perms, err := auth.GetUserPermissions(ctx, userID)
// perms.RoleLabel, perms.Permissions, perms.PermissionVersion
```

### ResetToRoleTemplate

Resets user to their base role's current template.

```go
func (a *Auth[T]) ResetToRoleTemplate(ctx context.Context, userID string) error
```

### HasPermission

Checks if a permission set includes a required permission.

```go
func HasPermission(permissions []string, required string) bool
```

**Example:**
```go
if goauth.HasPermission(claims.Permissions, "monitors:delete") {
    // User can delete monitors
}
```

### InitUserPermissions

Initializes permissions for a new user.

```go
func (a *Auth[T]) InitUserPermissions(ctx context.Context, userID string, role string) error
```

### DeleteUserPermissions

Removes a user's permission record (when user is deleted).

```go
func (a *Auth[T]) DeleteUserPermissions(ctx context.Context, userID string) error
```

---

## RBAC Registry (Read-Only) 🔐

> **Note:** These methods require RBAC to be enabled.

### GetPermissionGroups

Gets all permission groups (for UI rendering).

```go
func (a *Auth[T]) GetPermissionGroups() []PermissionGroup
```

### GetRoleTemplates

Gets all role templates (for UI dropdowns).

```go
func (a *Auth[T]) GetRoleTemplates() []RoleTemplate
```

### GetAllPermissions

Gets flat list of all permissions.

```go
func (a *Auth[T]) GetAllPermissions() []Permission
```

---

## Middleware

### Middleware()

Returns the middleware instance for the configured framework.

```go
func (a *Auth[T]) Middleware() *Middleware[T]
```

**Example:**
```go
// For net/http
mw := auth.Middleware()
http.Handle("/api/", mw.Authenticate(handler))
```

---

## Utility

### Close

Closes the auth instance and stops background workers.

```go
func (a *Auth[T]) Close() error
```

### ClaimsFromContext

Extracts claims from request context.

```go
func ClaimsFromContext[T Claims](ctx context.Context) *T
```

**Example:**
```go
func handler(w http.ResponseWriter, r *http.Request) {
    claims := goauth.ClaimsFromContext[MyClaims](r.Context())
    userID := claims.UserID
}
```
