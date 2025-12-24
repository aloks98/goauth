# GoAuth

A stateful authentication and authorization library for Go applications.

[![Go Reference](https://pkg.go.dev/badge/github.com/aloks98/goauth.svg)](https://pkg.go.dev/github.com/aloks98/goauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/aloks98/goauth)](https://goreportcard.com/report/github.com/aloks98/goauth)
[![CI](https://github.com/aloks98/goauth/actions/workflows/ci.yml/badge.svg)](https://github.com/aloks98/goauth/actions/workflows/ci.yml)

## Features

- **JWT Access Tokens** - Short-lived tokens with custom claims
- **Refresh Token Rotation** - Secure token refresh with family tracking
- **Token Blacklisting** - Instant revocation support
- **Password Hashing** - Argon2id (default) or Bcrypt
- **API Key Management** - Scoped API keys with expiration
- **User-Level RBAC** - Role templates with per-user permissions
- **Config-Driven** - Define roles/permissions in YAML or JSON
- **Multi-Framework** - Middleware for Gin, Echo, Fiber, Chi, and net/http

## Installation

```bash
go get github.com/aloks98/goauth
```

## Quick Start

### Basic Authentication (No RBAC)

```go
package main

import (
    "context"
    "log"

    "github.com/aloks98/goauth"
    "github.com/aloks98/goauth/store/memory"
)

// Define your custom claims
type Claims struct {
    goauth.StandardClaims
    Email string `json:"email"`
}

func main() {
    // Create auth instance
    auth, err := goauth.New[*Claims](
        goauth.WithSecret("your-256-bit-secret-key-here"),
        goauth.WithStore(memory.New()),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    ctx := context.Background()

    // Generate token pair for a user
    tokens, err := auth.GenerateTokenPair(ctx, "user-123", &Claims{
        Email: "user@example.com",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Access Token: %s", tokens.AccessToken)

    // Validate access token
    claims, err := auth.ValidateAccessToken(ctx, tokens.AccessToken)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("User ID: %s, Email: %s", claims.UserID, claims.Email)

    // Refresh tokens
    newTokens, err := auth.RefreshTokens(ctx, tokens.RefreshToken)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("New Access Token: %s", newTokens.AccessToken)
}
```

### With RBAC (Role-Based Access Control)

Create a `permissions.yaml` file:

```yaml
roles:
  admin:
    permissions:
      - "*"
  editor:
    permissions:
      - "posts:read"
      - "posts:create"
      - "posts:update"
  viewer:
    permissions:
      - "posts:read"
```

```go
package main

import (
    "context"
    "log"

    "github.com/aloks98/goauth"
    "github.com/aloks98/goauth/store/sql"
)

type Claims struct {
    goauth.StandardClaims
    TenantID string `json:"tenant_id"`
}

func main() {
    // Create store
    store, err := sql.NewPostgres("postgres://user:pass@localhost/mydb?sslmode=disable")
    if err != nil {
        log.Fatal(err)
    }

    // Create auth with RBAC
    auth, err := goauth.New[*Claims](
        goauth.WithSecret("your-256-bit-secret-key-here"),
        goauth.WithStore(store),
        goauth.WithRBACFromFile("./permissions.yaml"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    ctx := context.Background()

    // Assign a role to user
    err = auth.AssignRole(ctx, "user-123", "editor")
    if err != nil {
        log.Fatal(err)
    }

    // Check permissions
    hasPermission, err := auth.HasPermission(ctx, "user-123", "posts:create")
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Can create posts: %v", hasPermission) // true

    // Add custom permissions
    err = auth.AddPermissions(ctx, "user-123", []string{"posts:delete"})
    if err != nil {
        log.Fatal(err)
    }
}
```

### HTTP Middleware

```go
package main

import (
    "net/http"

    "github.com/aloks98/goauth"
    "github.com/aloks98/goauth/middleware"
    "github.com/aloks98/goauth/store/memory"
)

type Claims struct {
    goauth.StandardClaims
}

func main() {
    auth, _ := goauth.New[*Claims](
        goauth.WithSecret("your-secret"),
        goauth.WithStore(memory.New()),
    )

    // Create adapter for middleware
    adapter := &AuthAdapter{auth: auth}

    // Create middleware
    authMiddleware := middleware.Authenticate(adapter, adapter, nil)

    // Apply to routes
    mux := http.NewServeMux()
    mux.Handle("GET /protected", authMiddleware(http.HandlerFunc(protectedHandler)))

    http.ListenAndServe(":8080", mux)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    userID := middleware.GetUserID(r.Context())
    w.Write([]byte("Hello, " + userID))
}

// AuthAdapter implements middleware.TokenValidator and middleware.ClaimsExtractor
type AuthAdapter struct {
    auth *goauth.Auth[*Claims]
}

func (a *AuthAdapter) ValidateToken(ctx context.Context, token string) (interface{}, error) {
    return a.auth.ValidateAccessToken(ctx, token)
}

func (a *AuthAdapter) ExtractUserID(claims interface{}) string {
    if c, ok := claims.(*Claims); ok {
        return c.UserID
    }
    return ""
}
```

### Framework-Specific Middleware

**Gin:**
```go
import "github.com/aloks98/goauth/middleware/gin"

router.Use(ginmw.Authenticate(adapter))
router.GET("/protected", handler)
```

**Echo:**
```go
import "github.com/aloks98/goauth/middleware/echo"

e.Use(echomw.Authenticate(adapter))
e.GET("/protected", handler)
```

**Fiber:**
```go
import "github.com/aloks98/goauth/middleware/fiber"

app.Use(fibermw.Authenticate(adapter))
app.Get("/protected", handler)
```

**Chi:**
```go
import "github.com/aloks98/goauth/middleware/chi"

r.Use(chimw.Authenticate(adapter))
r.Get("/protected", handler)
```

## API Keys

```go
// Create an API key
key, err := auth.CreateAPIKey(ctx, "user-123", "My API Key", goauth.APIKeyOptions{
    Scopes:    []string{"read", "write"},
    ExpiresIn: 30 * 24 * time.Hour, // 30 days
})
// key.RawKey is only available once - store it securely!

// Validate API key
keyInfo, err := auth.ValidateAPIKey(ctx, rawKey)
if err != nil {
    // Invalid or expired
}

// List user's API keys
keys, err := auth.ListAPIKeys(ctx, "user-123")

// Revoke an API key
err = auth.RevokeAPIKey(ctx, keyID)
```

## Password Hashing

```go
// Hash a password (uses Argon2id by default)
hash, err := auth.HashPassword("user-password")

// Verify password
valid := auth.VerifyPassword("user-password", hash)
```

## Store Backends

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

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithSecret(secret)` | JWT signing secret (required) | - |
| `WithStore(store)` | Token/permission store (required) | - |
| `WithAccessTokenTTL(duration)` | Access token lifetime | 15 minutes |
| `WithRefreshTokenTTL(duration)` | Refresh token lifetime | 7 days |
| `WithRBACFromFile(path)` | Load RBAC config from file | - |
| `WithRBACFromBytes(data, format)` | Load RBAC config from bytes | - |
| `WithPasswordHasher(hasher)` | Custom password hasher | Argon2id |
| `WithCleanupInterval(duration)` | Expired token cleanup interval | 1 hour |

## Examples

### Basic Example
```bash
cd examples/basic
go run main.go
```

### RBAC Example
```bash
cd examples/with-rbac
go run main.go
```

### Full-Stack Demo Application

A complete demo application showcasing all GoAuth features with HTMX + Go templates:

```bash
cd examples/fullstack

# Run with different web frameworks:
make demo-http   # net/http
make demo-gin    # Gin
make demo-chi    # Chi
make demo-echo   # Echo
make demo-fiber  # Fiber
```

**Demo features:**
- User registration and login
- JWT authentication with cookies
- Token refresh flow
- API key management (create, list, revoke)
- RBAC management (assign roles, add permissions)
- Admin panel (user management, cleanup stats)
- HTMX-powered dynamic UI

**Demo users:**
| Email | Password | Role |
|-------|----------|------|
| admin@example.com | admin123 | admin |
| user@example.com | user123 | user |
| viewer@example.com | viewer123 | viewer |

See [examples/fullstack/README.md](examples/fullstack/README.md) for detailed setup instructions.

## Documentation

### Architecture
- [Overview](docs/architecture/01-overview.md) - Core principles and design
- [Package Structure](docs/architecture/02-package-structure.md) - Project layout
- [Token Service](docs/architecture/03-token-service.md) - JWT and refresh tokens
- [RBAC System](docs/architecture/04-rbac-system.md) - Roles and permissions
- [Store Interface](docs/architecture/05-store-interface.md) - Database adapters
- [Middleware](docs/architecture/06-middleware.md) - Framework integrations
- [API Reference](docs/architecture/07-api-reference.md) - Public API
- [Config Reference](docs/architecture/08-config-reference.md) - Configuration options
- [Database Schema](docs/architecture/09-database-schema.md) - Tables and migrations
- [OAuth Integration](docs/architecture/10-oauth-integration.md) - OAuth2/OIDC integration

## License

MIT License - see [LICENSE](LICENSE) for details.
