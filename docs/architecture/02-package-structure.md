# Package Structure

## Directory Layout

```
goauth/
├── goauth.go                 # Main entry point, builder pattern
├── config.go                 # Configuration structs and validation
├── claims.go                 # StandardClaims and generic handling
├── errors.go                 # Custom error types
├── options.go                # Functional options for builder
│
├── token/
│   ├── service.go            # Token service interface and implementation
│   ├── jwt.go                # JWT generation and validation
│   ├── refresh.go            # Refresh token logic with rotation
│   ├── blacklist.go          # Token blacklist management
│   └── claims.go             # Token claims helpers
│
├── password/
│   ├── hasher.go             # Hasher interface
│   ├── argon2.go             # Argon2id implementation (default)
│   └── bcrypt.go             # Bcrypt implementation
│
├── apikey/
│   ├── manager.go            # API key generation and validation
│   ├── config.go             # API key configuration
│   └── format.go             # Key format and parsing
│
├── rbac/
│   ├── rbac.go               # RBAC main interface
│   ├── config.go             # Config file structs (YAML/JSON)
│   ├── loader.go             # Config file loader
│   ├── validator.go          # Config validation
│   ├── registry.go           # Permission and role template storage
│   ├── permission.go         # Permission struct and wildcard matching
│   ├── resolver.go           # User permission resolution
│   └── sync.go               # Startup sync logic
│
├── store/
│   ├── store.go              # Store interface definition
│   ├── models.go             # Database models
│   ├── memory/
│   │   └── memory.go         # In-memory store (testing)
│   ├── redis/
│   │   └── redis.go          # Redis store implementation
│   └── sql/
│       ├── sql.go            # Generic SQL implementation
│       ├── postgres.go       # PostgreSQL-specific
│       ├── mysql.go          # MySQL-specific
│       ├── sqlite.go         # SQLite-specific
│       └── migrations.go     # Auto-migration logic
│
├── middleware/
│   ├── middleware.go         # Core middleware logic
│   ├── http.go               # net/http middleware
│   ├── fiber.go              # Fiber adapter
│   ├── echo.go               # Echo adapter
│   ├── gin.go                # Gin adapter
│   └── chi.go                # Chi adapter
│
├── ratelimit/
│   ├── limiter.go            # Rate limiter interface
│   ├── sliding.go            # Sliding window implementation
│   └── config.go             # Rate limit configuration
│
├── cleanup/
│   └── worker.go             # Background cleanup worker
│
└── internal/
    ├── crypto/
    │   └── random.go         # Secure random generation
    └── hash/
        └── hash.go           # Hashing utilities
```

## Package Responsibilities

### Root Package (`goauth`)

Main entry point and public API.

| File | Purpose |
|------|---------|
| `goauth.go` | `Auth[T]` struct, `New[T]()` constructor, high-level methods |
| `config.go` | Configuration structs, validation |
| `claims.go` | `StandardClaims`, generic constraints |
| `errors.go` | All public error types |
| `options.go` | Functional options (`WithSecret`, `WithStore`, etc.) |

### Token Package (`token`)

JWT and refresh token handling.

| File | Purpose |
|------|---------|
| `service.go` | `TokenService` interface and implementation |
| `jwt.go` | JWT creation, signing, validation |
| `refresh.go` | Refresh token generation, rotation, family tracking |
| `blacklist.go` | Access token blacklist operations |
| `claims.go` | Claims extraction and manipulation |

### Password Package (`password`)

Password hashing implementations.

| File | Purpose |
|------|---------|
| `hasher.go` | `Hasher` interface |
| `argon2.go` | Argon2id implementation with configurable params |
| `bcrypt.go` | Bcrypt implementation for compatibility |

### API Key Package (`apikey`)

API key generation and validation.

| File | Purpose |
|------|---------|
| `manager.go` | `Manager` interface, generation, validation |
| `config.go` | Configuration (prefix, length, etc.) |
| `format.go` | Key format parsing, prefix extraction |

### RBAC Package (`rbac`)

Role-based access control.

| File | Purpose |
|------|---------|
| `rbac.go` | Main `RBAC` interface |
| `config.go` | Config file structs |
| `loader.go` | YAML/JSON file loading |
| `validator.go` | Config validation rules |
| `registry.go` | In-memory permission/role storage |
| `permission.go` | Permission matching (including wildcards) |
| `resolver.go` | Resolve effective permissions for a user |
| `sync.go` | Startup sync logic for role templates |

### Store Package (`store`)

Data persistence layer.

| File | Purpose |
|------|---------|
| `store.go` | `Store` interface definition |
| `models.go` | Shared database models |
| `memory/memory.go` | In-memory implementation for testing |
| `redis/redis.go` | Redis implementation |
| `sql/sql.go` | Generic SQL implementation |
| `sql/postgres.go` | PostgreSQL dialect and optimizations |
| `sql/mysql.go` | MySQL dialect |
| `sql/sqlite.go` | SQLite dialect |
| `sql/migrations.go` | Table creation and migrations |

### Middleware Package (`middleware`)

HTTP middleware for various frameworks.

| File | Purpose |
|------|---------|
| `middleware.go` | Core middleware logic (framework-agnostic) |
| `http.go` | Standard `net/http` middleware |
| `fiber.go` | Fiber framework adapter |
| `echo.go` | Echo framework adapter |
| `gin.go` | Gin framework adapter |
| `chi.go` | Chi router adapter |

### Rate Limit Package (`ratelimit`)

Optional rate limiting.

| File | Purpose |
|------|---------|
| `limiter.go` | `Limiter` interface |
| `sliding.go` | Sliding window algorithm |
| `config.go` | Rate limit rules configuration |

### Cleanup Package (`cleanup`)

Background maintenance.

| File | Purpose |
|------|---------|
| `worker.go` | Periodic cleanup of expired tokens |

### Internal Package (`internal`)

Shared utilities (not exported).

| File | Purpose |
|------|---------|
| `crypto/random.go` | Cryptographically secure random strings |
| `hash/hash.go` | SHA256, comparison utilities |

## Dependency Graph

```
goauth (root)
    ├── token
    │   └── store (interface only)
    ├── password
    │   └── (no dependencies)
    ├── apikey
    │   ├── store (interface only)
    │   └── internal/crypto
    ├── rbac
    │   └── store (interface only)
    ├── store
    │   └── (external: database drivers)
    ├── middleware
    │   ├── token
    │   ├── rbac
    │   └── (external: framework packages)
    ├── ratelimit
    │   └── store (interface only)
    └── cleanup
        └── store (interface only)
```

## Import Rules

1. **No circular imports**: Lower packages never import higher packages
2. **Store is interface**: All packages depend on store interface, not implementations
3. **Internal is private**: Only root package can import internal packages
4. **Middleware imports core**: Middleware can import token, rbac, etc.
