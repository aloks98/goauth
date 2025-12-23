# CLAUDE.md - GoAuth Project Guide

## Project Overview

GoAuth is a stateful authentication and authorization library for Go. It provides JWT tokens, refresh token rotation, API keys, and user-level RBAC.

## Key Architecture Decisions

1. **Stateful Only**: Requires a database store (no pure stateless mode)
2. **RBAC is Optional**: Use full RBAC or just simple token-based auth
3. **User-Level Permissions**: When RBAC enabled, permissions stored per-user, not derived from roles
4. **Role Templates**: Roles are templates that copy permissions to users
5. **Config Files for RBAC**: Permissions defined in YAML/JSON, not code
6. **Startup Sync**: Role template changes sync to users on app restart
7. **Generic Claims**: Uses Go generics for custom JWT claims

## Two Modes

### Simple Mode (No RBAC)
```go
auth, _ := goauth.New[Claims](
    goauth.WithSecret("..."),
    goauth.WithStore(store),
    // No RBAC config = simple mode
)
```
- JWT + refresh tokens ✅
- API keys ✅
- `Authenticate()` middleware ✅
- `RequirePermission()` ❌ (returns ErrRBACNotEnabled)

### Full Mode (With RBAC)
```go
auth, _ := goauth.New[Claims](
    goauth.WithSecret("..."),
    goauth.WithStore(store),
    goauth.WithRBACFromFile("./permissions.yaml"),  // Enables RBAC
)
```
- Everything above ✅
- `RequirePermission()` ✅
- `AssignRole()` / `AddPermissions()` ✅
- Permission version tracking ✅
- Role sync on startup ✅

## Directory Structure

```
goauth/
├── goauth.go           # Main entry, Auth[T] struct, New[T]()
├── config.go           # Configuration structs
├── claims.go           # StandardClaims, Claims constraint
├── errors.go           # All error types
├── options.go          # Functional options (With*)
├── token/              # JWT and refresh tokens
├── apikey/             # API key management
├── rbac/               # Permissions, roles, sync
├── store/              # Database adapters
│   ├── memory/         # For testing
│   └── sql/            # Postgres, MySQL
├── middleware/         # HTTP framework adapters
├── ratelimit/          # Optional rate limiting
├── cleanup/            # Background workers
└── internal/           # Private utilities
```

## Important Patterns

### Generic Claims
```go
type MyClaims struct {
    goauth.StandardClaims  // Must embed this
    TenantID string `json:"tenant_id"`
}

auth, _ := goauth.New[MyClaims](...)
```

### Functional Options
```go
auth, _ := goauth.New[MyClaims](
    goauth.WithSecret("..."),
    goauth.WithStore(store),
    goauth.WithRBACFromFile("./permissions.yaml"),
)
```

### Permission Format
```
resource:action     # monitors:read
resource:*          # monitors:* (all actions)
*:action            # *:read (all resources)
*                   # superuser
```

### Role Label Logic
- Matches template → `role_label = "editor"`
- Customized → `role_label = "custom"`
- Track `base_role` for reset capability

## Common Tasks

### Adding a New Store
1. Implement `Store` interface in `store/store.go`
2. Add constructor in new package (e.g., `store/mongodb/`)
3. Add factory function
4. Add integration tests

### Adding a New Middleware
1. Create adapter file (e.g., `middleware/newframework.go`)
2. Wrap core logic from `middleware/middleware.go`
3. Add `ClaimsFromNewFramework[T]()` helper
4. Add tests and example

### Adding a New Error
1. Define in `errors.go` with `Err` prefix
2. Add to error code map in `middleware/middleware.go`
3. Document in API reference

## Testing Commands

```bash
# Unit tests
go test ./...

# With coverage
go test ./... -coverprofile=coverage.out

# Integration tests (requires Docker)
docker-compose -f docker-compose.test.yml up -d
go test ./... -tags=integration
docker-compose -f docker-compose.test.yml down

# Lint
golangci-lint run
```

## Code Style

- Use `context.Context` as first parameter
- Return errors, don't panic
- Use table-driven tests
- Document all exported symbols
- Keep packages focused and small

## Dependencies

**Required:**
- `github.com/golang-jwt/jwt/v5` - JWT handling
- `golang.org/x/crypto` - cryptographic utilities
- Database drivers as needed

**Optional (for specific stores/middleware):**
- `github.com/gofiber/fiber/v2`
- `github.com/labstack/echo/v4`
- `github.com/gin-gonic/gin`
- `github.com/go-chi/chi/v5`
- `github.com/jackc/pgx/v5`

## Implementation Order

1. **Phase 1**: Foundation (errors, config, interfaces)
2. **Phase 2**: Token service (JWT, refresh, blacklist)
3. **Phase 3**: API keys
4. **Phase 4**: RBAC (config, permissions, sync)
5. **Phase 5**: Stores (memory, SQL)
6. **Phase 6**: Middleware adapters
7. **Phase 7**: Rate limiting, cleanup
8. **Phase 8**: Testing, docs, examples

## OAuth Integration (External Libraries)

GoAuth works with OAuth using external libraries - no built-in adapters. Use `golang.org/x/oauth2` for OAuth flows and `github.com/coreos/go-oidc/v3` for OIDC verification, then call GoAuth for your own tokens.

### Flow
1. User authenticates with provider (Google, GitHub, etc.)
2. Your app verifies provider token (using external library)
3. Your app finds/creates user in YOUR database
4. Your app calls `auth.GenerateTokenPair(userID, claims)`
5. Client uses YOUR tokens (not provider tokens)

### Key Points
- GoAuth doesn't manage users - you do
- Provider tokens are only for identity verification
- Your app issues its own tokens via GoAuth
- Link multiple providers to one user in YOUR database
- See `architecture/10-oauth-integration.md` for complete examples

## Critical Flows

### Token Generation
1. Fetch user permissions from store
2. Get permission version
3. Generate JWT with version in claims
4. Generate refresh token
5. Store refresh token with family ID

### Token Validation
1. Parse JWT, verify signature
2. Check expiry
3. Check blacklist
4. Check permission version matches current
5. Return claims or specific error

### Refresh with Rotation
1. Validate refresh token
2. Check not revoked
3. Mark old token revoked
4. Generate new pair (same family)
5. If old token reused → revoke family (theft!)

### Role Template Sync
1. On startup, compare config with stored templates
2. For changed templates, find users with matching `role_label`
3. Update permissions, bump version
4. Skip users with `role_label = "custom"`

## Things to Remember

- Never store raw refresh tokens (store hash)
- Never return raw API keys after creation (show once)
- Always bump permission version on changes
- Blacklist entries should have TTL matching token expiry
- Use constant-time comparison for security-sensitive values
- Handle clock skew for JWT validation
- Log security events (failed logins, token reuse)

## Documentation Links

- Architecture: `docs/architecture/`
- Implementation Phases: `docs/phases/`
- Testing Strategy: `docs/testing/testing-strategy.md`
