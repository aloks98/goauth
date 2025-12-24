# Getting Started with GoAuth

This guide will help you integrate GoAuth into your Go application.

## Table of Contents

1. [Installation](#installation)
2. [Basic Setup](#basic-setup)
3. [Authentication Flow](#authentication-flow)
4. [Adding RBAC](#adding-rbac)
5. [API Keys](#api-keys)
6. [Framework Integration](#framework-integration)
7. [Production Considerations](#production-considerations)

---

## Installation

```bash
go get github.com/aloks98/goauth
```

**Optional database drivers:**

```bash
# PostgreSQL
go get github.com/jackc/pgx/v5

# MySQL
go get github.com/go-sql-driver/mysql
```

---

## Basic Setup

### Step 1: Define Your Claims

Create a custom claims type that embeds `StandardClaims`:

```go
package main

import "github.com/aloks98/goauth"

// MyClaims defines the data stored in JWT tokens
type MyClaims struct {
    goauth.StandardClaims
    Email string `json:"email"`
    Name  string `json:"name"`
}
```

### Step 2: Create the Auth Instance

```go
package main

import (
    "log"

    "github.com/aloks98/goauth"
    "github.com/aloks98/goauth/store/memory"
)

func main() {
    // Create a store (use sql.NewPostgres for production)
    store := memory.New()

    // Create the auth instance
    auth, err := goauth.New[*MyClaims](
        goauth.WithSecret("your-256-bit-secret-key-minimum-32-chars"),
        goauth.WithStore(store),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    // Use auth...
}
```

### Step 3: Generate Tokens

When a user logs in successfully:

```go
func login(auth *goauth.Auth[*MyClaims], email, password string) (*token.Pair, error) {
    // 1. Verify credentials (your logic)
    user, err := verifyCredentials(email, password)
    if err != nil {
        return nil, err
    }

    // 2. Generate tokens
    tokens, err := auth.GenerateTokenPair(ctx, user.ID, map[string]any{
        "email": user.Email,
        "name":  user.Name,
    })
    if err != nil {
        return nil, err
    }

    return tokens, nil
}
```

### Step 4: Validate Tokens

On protected routes:

```go
func protectedHandler(auth *goauth.Auth[*MyClaims], tokenString string) error {
    claims, err := auth.ValidateAccessToken(ctx, tokenString)
    if err != nil {
        return err // Token invalid, expired, or revoked
    }

    // Access claims
    userID := claims.UserID
    email := claims.Custom["email"].(string)

    // Process request...
    return nil
}
```

### Step 5: Refresh Tokens

When access token expires:

```go
func refresh(auth *goauth.Auth[*MyClaims], refreshToken string) (*token.Pair, error) {
    newTokens, err := auth.RefreshTokens(ctx, refreshToken)
    if err != nil {
        // Refresh token invalid - user must re-login
        return nil, err
    }
    return newTokens, nil
}
```

---

## Authentication Flow

```
┌─────────┐                    ┌─────────┐                    ┌─────────┐
│  Client │                    │  Server │                    │  Store  │
└────┬────┘                    └────┬────┘                    └────┬────┘
     │                              │                              │
     │  1. POST /login              │                              │
     │  {email, password}           │                              │
     │─────────────────────────────>│                              │
     │                              │                              │
     │                              │  2. Verify credentials       │
     │                              │─────────────────────────────>│
     │                              │<─────────────────────────────│
     │                              │                              │
     │                              │  3. GenerateTokenPair()      │
     │                              │─────────────────────────────>│
     │                              │<─────────────────────────────│
     │                              │                              │
     │  4. {access_token,           │                              │
     │      refresh_token}          │                              │
     │<─────────────────────────────│                              │
     │                              │                              │
     │  5. GET /protected           │                              │
     │  Authorization: Bearer xxx   │                              │
     │─────────────────────────────>│                              │
     │                              │                              │
     │                              │  6. ValidateAccessToken()    │
     │                              │─────────────────────────────>│
     │                              │<─────────────────────────────│
     │                              │                              │
     │  7. {protected data}         │                              │
     │<─────────────────────────────│                              │
     │                              │                              │
     │  8. POST /refresh            │                              │
     │  {refresh_token}             │                              │
     │─────────────────────────────>│                              │
     │                              │                              │
     │                              │  9. RefreshTokens()          │
     │                              │  (with rotation)             │
     │                              │─────────────────────────────>│
     │                              │<─────────────────────────────│
     │                              │                              │
     │  10. {new tokens}            │                              │
     │<─────────────────────────────│                              │
```

---

## Adding RBAC

### Step 1: Create permissions.yaml

```yaml
# permissions.yaml
version: "1"

permission_groups:
  - key: posts
    name: Posts
    permissions:
      - key: posts:read
        name: Read Posts
      - key: posts:create
        name: Create Posts
      - key: posts:update
        name: Update Posts
      - key: posts:delete
        name: Delete Posts

  - key: users
    name: Users
    permissions:
      - key: users:read
        name: Read Users
      - key: users:update
        name: Update Users

roles:
  - key: admin
    name: Administrator
    description: Full access to everything
    permissions:
      - "*"  # Superuser

  - key: editor
    name: Editor
    description: Can manage posts
    permissions:
      - posts:*  # All post permissions

  - key: viewer
    name: Viewer
    description: Read-only access
    permissions:
      - posts:read
      - users:read
```

### Step 2: Enable RBAC

```go
auth, err := goauth.New[*MyClaims](
    goauth.WithSecret("your-secret"),
    goauth.WithStore(store),
    goauth.WithRBACFromFile("./permissions.yaml"),
)
```

### Step 3: Assign Roles

```go
// When creating a user or updating their role
err := auth.AssignRole(ctx, userID, "editor")
```

### Step 4: Check Permissions

```go
// Check single permission
canDelete, err := auth.HasPermission(ctx, userID, "posts:delete")

// Check multiple permissions
canManage, err := auth.HasAllPermissions(ctx, userID, []string{
    "posts:create",
    "posts:update",
})

// Require permission (returns error if denied)
err := auth.RequirePermission(ctx, userID, "admin:access")
if err != nil {
    return errors.New("admin access required")
}
```

### Step 5: Modify Permissions

```go
// Add extra permissions
err := auth.AddPermissions(ctx, userID, []string{"reports:read"})

// Remove permissions
err := auth.RemovePermissions(ctx, userID, []string{"posts:delete"})

// Reset to original role
err := auth.ResetToRole(ctx, userID)
```

---

## API Keys

### Generate API Key

```go
key, err := auth.CreateAPIKey(ctx, userID, &apikey.CreateKeyOptions{
    Name:   "Production API Key",
    Scopes: []string{"read"},         // Limit to read-only
    TTL:    30 * 24 * time.Hour,      // Expires in 30 days
})
if err != nil {
    return err
}

// IMPORTANT: Show key.RawKey to user - it won't be available again!
fmt.Printf("Your API Key: %s\n", key.RawKey)
fmt.Printf("Key ID: %s\n", key.ID)
```

### Validate API Key

```go
result, err := auth.ValidateAPIKey(ctx, rawKey)
if err != nil {
    // Invalid, expired, or revoked
    return err
}

userID := result.UserID
scopes := result.Key.Scopes
```

### Validate with Scope

```go
result, err := auth.ValidateAPIKeyWithScope(ctx, rawKey, "write")
if err != nil {
    // Key doesn't have "write" scope
    return err
}
```

### List & Revoke

```go
// List user's keys
keys, err := auth.ListAPIKeys(ctx, userID)
for _, key := range keys {
    fmt.Printf("%s: %s...%s (expires: %v)\n",
        key.Name, key.Prefix, key.Hint, key.ExpiresAt)
}

// Revoke a key
err := auth.RevokeAPIKey(ctx, keyID)
```

---

## Framework Integration

### Gin

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/aloks98/goauth/middleware/gin"
)

func setupRoutes(r *gin.Engine, auth *goauth.Auth[*MyClaims]) {
    adapter := NewAdapter(auth)

    // Protected routes
    protected := r.Group("/api")
    protected.Use(ginmw.Authenticate(adapter))
    {
        protected.GET("/me", meHandler)
        protected.GET("/posts", postsHandler)
    }
}

// Adapter implementation
type Adapter struct {
    auth *goauth.Auth[*MyClaims]
}

func (a *Adapter) ValidateToken(ctx context.Context, token string) (any, error) {
    return a.auth.ValidateAccessToken(ctx, token)
}

func (a *Adapter) ExtractUserID(claims any) string {
    if c, ok := claims.(*token.Claims); ok {
        return c.UserID
    }
    return ""
}
```

### Echo

```go
import (
    "github.com/labstack/echo/v4"
    "github.com/aloks98/goauth/middleware/echo"
)

func setupRoutes(e *echo.Echo, auth *goauth.Auth[*MyClaims]) {
    adapter := NewAdapter(auth)

    api := e.Group("/api")
    api.Use(echomw.Authenticate(adapter))
    api.GET("/me", meHandler)
}
```

### Chi

```go
import (
    "github.com/go-chi/chi/v5"
    "github.com/aloks98/goauth/middleware/chi"
)

func setupRoutes(r chi.Router, auth *goauth.Auth[*MyClaims]) {
    adapter := NewAdapter(auth)

    r.Route("/api", func(r chi.Router) {
        r.Use(chimw.Authenticate(adapter))
        r.Get("/me", meHandler)
    })
}
```

### Fiber

```go
import (
    "github.com/gofiber/fiber/v2"
    "github.com/aloks98/goauth/middleware/fiber"
)

func setupRoutes(app *fiber.App, auth *goauth.Auth[*MyClaims]) {
    adapter := NewAdapter(auth)

    api := app.Group("/api")
    api.Use(fibermw.Authenticate(adapter))
    api.Get("/me", meHandler)
}
```

---

## Production Considerations

### 1. Use a Real Database

```go
import "github.com/aloks98/goauth/store/sql"

// PostgreSQL (recommended)
store, err := sql.NewPostgres("postgres://user:pass@localhost/myapp?sslmode=require")

// MySQL
store, err := sql.NewMySQL("user:pass@tcp(localhost:3306)/myapp?parseTime=true")
```

### 2. Strong Secret Key

Generate a secure random secret:

```bash
openssl rand -base64 32
```

```go
auth, _ := goauth.New[*MyClaims](
    goauth.WithSecret(os.Getenv("AUTH_SECRET")), // At least 32 chars
    // ...
)
```

### 3. Configure Token TTLs

```go
auth, _ := goauth.New[*MyClaims](
    goauth.WithAccessTokenTTL(15 * time.Minute),   // Short-lived
    goauth.WithRefreshTokenTTL(7 * 24 * time.Hour), // Longer-lived
    // ...
)
```

### 4. Enable Auto-Migration (Development Only)

```go
// Development
auth, _ := goauth.New[*MyClaims](
    goauth.WithAutoMigrate(true),
    // ...
)

// Production: Run migrations separately
// store.Migrate(ctx)
```

### 5. Handle Token Theft

```go
newTokens, err := auth.RefreshTokens(ctx, refreshToken)
if errors.Is(err, goauth.ErrRefreshTokenReused) {
    // Token was already used - possible theft!
    // Revoke all user tokens and force re-login
    auth.RevokeAllUserTokens(ctx, userID)
    return errors.New("security alert: please login again")
}
```

### 6. Secure Cookie Storage

```go
// Set tokens in HTTP-only, secure cookies
http.SetCookie(w, &http.Cookie{
    Name:     "access_token",
    Value:    tokens.AccessToken,
    HttpOnly: true,
    Secure:   true, // HTTPS only
    SameSite: http.SameSiteStrictMode,
    Path:     "/",
    MaxAge:   int(tokens.ExpiresIn),
})
```

### 7. Enable Cleanup Worker

```go
auth, _ := goauth.New[*MyClaims](
    goauth.WithCleanupInterval(1 * time.Hour), // Clean expired tokens
    // ...
)
```

---

## Next Steps

- See [API Reference](api-reference.md) for complete method documentation
- Check [Architecture Docs](architecture/) for design details
- Explore [Examples](../examples/) for full working code
