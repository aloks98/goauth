# Architecture Overview

## 1. Core Principles

- **Stateful by Design**: Requires a store (PostgreSQL, MySQL, SQLite, or Redis) for full functionality
- **RBAC is Optional**: Use full RBAC or just simple token-based auth
- **User-Level Permissions**: When RBAC enabled, permissions are assigned per-user, not just per-role
- **Role Templates**: Predefined permission sets that can be assigned to users
- **Config-Driven RBAC**: Permissions and roles defined via YAML/JSON config files
- **Startup Sync**: Role template changes automatically sync to users on application restart
- **Framework Agnostic**: Core is `net/http`, with adapters for popular frameworks
- **Generic Claims**: Applications define their own claims struct using Go generics

## 2. Two Modes of Operation

### Simple Mode (No RBAC)

For applications that just need authentication without complex permissions:

```go
auth, _ := goauth.New[Claims](
    goauth.WithSecret("..."),
    goauth.WithStore(store),
    // No RBAC config = simple mode
)

// Just generate and validate tokens
tokens, _ := auth.GenerateTokenPair(ctx, userID, Claims{
    Role: "admin",  // Put role in claims, handle authorization yourself
})
```

**Available features:**
- JWT access tokens with refresh rotation
- Token blacklisting
- Password hashing
- API keys (without scope validation)
- All middleware (except permission checks)

### Full Mode (With RBAC)

For applications that need user-level permissions:

```go
auth, _ := goauth.New[Claims](
    goauth.WithSecret("..."),
    goauth.WithStore(store),
    goauth.WithRBACFromFile("./permissions.yaml"),  // Enables RBAC
)

// Full permission management
auth.AssignRole(ctx, userID, "editor")
auth.AddPermissions(ctx, userID, []string{"billing:read"})
auth.RequirePermission("monitors:write")
```

**Additional features:**
- User-level permissions
- Role templates
- Permission version tracking
- Role sync on startup
- `RequirePermission()` middleware

## 3. Feature Summary

| Feature | Description | RBAC Required |
|---------|-------------|---------------|
| JWT Access Tokens | Short-lived tokens for API authentication | No |
| Refresh Tokens | Long-lived tokens with rotation and theft detection | No |
| Token Blacklisting | Instant token revocation | No |
| Password Hashing | Argon2id (default) and Bcrypt support | No |
| API Keys | Prefixed keys for programmatic access | No |
| API Key Scopes | Scope validation for API keys | Yes |
| User Permissions | Per-user permission management | Yes |
| Role Templates | Predefined permission sets | Yes |
| Permission Groups | Organized permissions for UI rendering | Yes |
| RequirePermission | Middleware permission checks | Yes |
| Role Sync | Auto-sync role changes on startup | Yes |
| Rate Limiting | Optional, configurable rate limiting | No |
| Multi-Framework | net/http, Fiber, Echo, Gin, Chi adapters | No |

## 4. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GoAuth Library                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                           Public API                                    │ │
│  │  goauth.New[T]() / GenerateTokenPair() / ValidateToken()              │ │
│  │  AssignRole() / SetPermissions() / GetUserPermissions()               │ │
│  │  GenerateAPIKey() / ValidateAPIKey() / HashPassword()                 │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│         ┌────────────────────────────┼────────────────────────────┐         │
│         ▼                            ▼                            ▼         │
│  ┌─────────────┐           ┌─────────────────┐           ┌─────────────┐   │
│  │   Token     │           │      RBAC       │           │   API Key   │   │
│  │   Service   │           │    Registry     │           │   Manager   │   │
│  │             │           │                 │           │             │   │
│  │ • JWT Gen   │           │ • Permissions   │           │ • Generate  │   │
│  │ • Validate  │           │ • Role Templates│           │ • Validate  │   │
│  │ • Refresh   │           │ • User Perms    │           │ • Revoke    │   │
│  │ • Blacklist │           │ • Sync Logic    │           │ • Scopes    │   │
│  └──────┬──────┘           └────────┬────────┘           └──────┬──────┘   │
│         │                           │                           │          │
│         └───────────────────────────┼───────────────────────────┘          │
│                                     ▼                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         Store Interface                                 │ │
│  │                                                                         │ │
│  │   ┌──────────────┐   ┌──────────────┐   ┌────────────────────────────┐ │ │
│  │   │    Redis     │   │    Memory    │   │           SQL              │ │ │
│  │   │              │   │   (testing)  │   │  PostgreSQL/MySQL/SQLite   │ │ │
│  │   └──────────────┘   └──────────────┘   └────────────────────────────┘ │ │
│  │                                                                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────┐  ┌─────────────────────────────────┐   │
│  │         Middleware              │  │        Password Hasher          │   │
│  │  net/http │ Fiber │ Echo │ Gin │  │     Argon2id │ Bcrypt           │   │
│  │          Chi                    │  │                                 │   │
│  └─────────────────────────────────┘  └─────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────┐  ┌─────────────────────────────────┐   │
│  │     Rate Limiter (Optional)     │  │      Background Workers         │   │
│  │     Sliding Window              │  │      Token Cleanup              │   │
│  └─────────────────────────────────┘  └─────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 5. Data Flow

### Authentication Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │────▶│   App    │────▶│  GoAuth  │────▶│  Store   │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                 │                │
     │  1. Login      │                 │                │
     │  credentials   │                 │                │
     │───────────────▶│                 │                │
     │                │  2. Validate    │                │
     │                │  (app logic)    │                │
     │                │                 │                │
     │                │  3. Generate    │                │
     │                │  token pair     │                │
     │                │────────────────▶│                │
     │                │                 │  4. Fetch      │
     │                │                 │  permissions   │
     │                │                 │───────────────▶│
     │                │                 │◀───────────────│
     │                │                 │                │
     │                │                 │  5. Store      │
     │                │                 │  refresh token │
     │                │                 │───────────────▶│
     │                │◀────────────────│                │
     │  6. Return     │                 │                │
     │  tokens        │                 │                │
     │◀───────────────│                 │                │
```

### Request Authorization Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │────▶│Middleware│────▶│  GoAuth  │────▶│  Store   │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                 │                │
     │  1. Request    │                 │                │
     │  + JWT token   │                 │                │
     │───────────────▶│                 │                │
     │                │  2. Validate    │                │
     │                │  JWT            │                │
     │                │────────────────▶│                │
     │                │                 │  3. Check      │
     │                │                 │  blacklist     │
     │                │                 │───────────────▶│
     │                │                 │◀───────────────│
     │                │                 │                │
     │                │                 │  4. Check      │
     │                │                 │  perm version  │
     │                │                 │───────────────▶│
     │                │                 │◀───────────────│
     │                │◀────────────────│                │
     │                │  5. Inject      │                │
     │                │  claims to ctx  │                │
     │                │                 │                │
     │  6. Process    │                 │                │
     │  request       │                 │                │
```

## 6. Design Decisions

### Why Stateful Only?

1. **Refresh Token Rotation**: Requires storing token state for theft detection
2. **Instant Revocation**: Blacklist must be persisted and checked
3. **User Permissions**: Per-user permissions need storage (when RBAC enabled)
4. **Role Sync**: Template changes require DB to track and sync

### Why RBAC Optional?

Not every app needs complex permissions:
- Simple apps may just need authentication
- Some apps use external authorization (Casbin, OPA)
- Microservices might just validate tokens
- Simple role-in-claims is sufficient for many cases

### Why User-Level Permissions (When RBAC Enabled)?

Roles are convenient but inflexible. Real apps need:
- Custom permission sets per user
- Temporary elevated access
- Granular access control

Role templates provide convenience while user-level permissions provide flexibility.

### Why Config Files for RBAC?

1. **Version Control**: Permissions changes are tracked in git
2. **Review Process**: Changes go through PR review
3. **Environment Parity**: Same permissions across dev/staging/prod
4. **Startup Validation**: Catch errors before app runs
