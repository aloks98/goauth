# GoAuth - Authentication & Authorization Library for Go

A stateful, pluggable authentication and authorization library for Go applications.

## Features

- JWT access tokens with refresh token rotation
- Token blacklisting for instant revocation
- Password hashing (Argon2id / Bcrypt)
- API key management with scopes
- User-level RBAC with role templates
- Config-driven permissions (YAML/JSON)
- Automatic role sync on startup
- Multi-framework middleware support

## Documentation

### Architecture

- [01-overview.md](./architecture/01-overview.md) - Core principles and features
- [02-package-structure.md](./architecture/02-package-structure.md) - Project layout
- [03-token-service.md](./architecture/03-token-service.md) - JWT and refresh tokens
- [04-rbac-system.md](./architecture/04-rbac-system.md) - Roles and permissions
- [05-store-interface.md](./architecture/05-store-interface.md) - Database adapters
- [06-middleware.md](./architecture/06-middleware.md) - Framework integrations
- [07-api-reference.md](./architecture/07-api-reference.md) - Public API
- [08-config-reference.md](./architecture/08-config-reference.md) - Configuration options
- [09-database-schema.md](./architecture/09-database-schema.md) - Tables and migrations
- [10-oauth-integration.md](./architecture/10-oauth-integration.md) - OAuth2/OIDC integration

### Implementation Phases

- [phase-1-foundation.md](plans/phase-1-foundation.md) - Core setup and interfaces
- [phase-2-token-service.md](plans/phase-2-token-service.md) - JWT and refresh tokens
- [phase-3-password-apikey.md](plans/phase-3-password-apikey.md) - Password hashing and API keys
- [phase-4-rbac.md](plans/phase-4-rbac.md) - RBAC system
- [phase-5-store.md](plans/phase-5-store.md) - Store implementations
- [phase-6-middleware.md](plans/phase-6-middleware.md) - Framework middleware
- [phase-7-extras.md](plans/phase-7-extras.md) - Rate limiting and cleanup
- [phase-8-testing-docs.md](plans/phase-8-testing-docs.md) - Testing and documentation

### Testing

- [testing-strategy.md](./testing/testing-strategy.md) - Testing approach and guidelines

## Quick Start

### Simple Mode (Auth Only)

```go
package main

import (
    "github.com/yourusername/goauth"
    "github.com/yourusername/goauth/store/sql"
)

type MyClaims struct {
    goauth.StandardClaims
    Role string `json:"role"`
}

func main() {
    auth, err := goauth.New[MyClaims](
        goauth.WithSecret("your-256-bit-secret"),
        goauth.WithStore(sql.Postgres("postgres://localhost/myapp")),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    // Generate tokens
    tokens, _ := auth.GenerateTokenPair(ctx, userID, MyClaims{
        Role: "admin",
    })

    // Validate in middleware, check role in handlers
}
```

### Full Mode (With RBAC)

```go
package main

import (
    "github.com/yourusername/goauth"
    "github.com/yourusername/goauth/store/sql"
)

type MyClaims struct {
    goauth.StandardClaims
    TenantID string `json:"tenant_id"`
}

func main() {
    auth, err := goauth.New[MyClaims](
        goauth.WithSecret("your-256-bit-secret"),
        goauth.WithStore(sql.Postgres("postgres://localhost/myapp")),
        goauth.WithRBACFromFile("./config/permissions.yaml"),
        goauth.WithAutoMigrate(true),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    // Assign roles and permissions
    auth.AssignRole(ctx, userID, "editor")
    
    // Use permission middleware
    mw := auth.Middleware()
    router.Handle("/api/", mw.RequirePermission("monitors:read")(handler))
}
```

## License

MIT
