# Phase 1: Foundation

**Duration:** 3-4 days
**Goal:** Set up project structure, core interfaces, configuration, and error types.
**Status:** ✅ COMPLETE

---

## Tasks

### 1.1 Project Setup

**Description:** Initialize Go module and create directory structure.

**Estimated Hours:** 1

**Acceptance Criteria:**
- [x] Go module initialized with `github.com/aloks98/goauth`
- [x] Directory structure matches architecture doc
- [x] `.gitignore` includes appropriate patterns
- [x] `Makefile` with common commands (test, lint, build)
- [x] CI workflow file (GitHub Actions)

**Testing:**
```bash
go mod tidy  # No errors
make lint    # Passes
```

---

### 1.2 Define Error Types

**Description:** Create all custom error types in `errors.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] All error types defined as package-level variables
- [x] `AuthError` struct with `Code`, `Message`, `Err` fields
- [x] Errors implement `error` interface
- [x] Errors implement `Unwrap()` for `errors.Is()` support
- [x] Error codes defined as constants

**Errors to implement:**
```go
// Token errors
ErrTokenExpired
ErrTokenNotYetValid
ErrTokenMalformed
ErrTokenInvalidSig
ErrTokenBlacklisted
ErrPermissionsChanged

// Refresh token errors
ErrRefreshTokenReused
ErrRefreshTokenExpired
ErrRefreshTokenInvalid
ErrTokenFamilyRevoked

// API key errors
ErrAPIKeyInvalid
ErrAPIKeyExpired
ErrAPIKeyRevoked

// Password errors
ErrPasswordTooWeak
ErrPasswordMismatch

// Rate limit errors
ErrRateLimitExceeded

// Store errors
ErrStoreRequired
ErrStoreUnavailable
ErrStoreTimeout

// Config errors
ErrConfigInvalid
ErrConfigVersionUnsupported
ErrDuplicatePermission
ErrDuplicateRole
ErrRolePermissionNotFound
ErrEmptyPermissionKey
ErrInvalidPermissionFormat

// Permission errors
ErrPermissionDenied
ErrUserPermissionsNotFound

// RBAC mode errors
ErrRBACNotEnabled
```

**Testing:**
- [x] Unit test: `errors.Is(wrappedErr, ErrTokenExpired)` returns true
- [x] Unit test: `AuthError.Error()` returns meaningful message
- [x] Unit test: `AuthError.Unwrap()` returns underlying error

---

### 1.3 Define Standard Claims

**Description:** Create `StandardClaims` struct and generic constraints in `claims.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] `StandardClaims` struct with all required fields
- [x] `Claims` interface/constraint for generic type parameter
- [x] Helper methods: `IsExpired()`, `GetUserID()`, `GetJTI()`
- [x] JSON tags for all fields

**Implementation:**
```go
type StandardClaims struct {
    UserID            string `json:"sub"`
    JTI               string `json:"jti"`
    IssuedAt          int64  `json:"iat"`
    ExpiresAt         int64  `json:"exp"`
    PermissionVersion int    `json:"pv"`
}

type Claims interface {
    GetStandardClaims() *StandardClaims
}
```

**Testing:**
- [x] Unit test: `StandardClaims` serializes to JSON correctly
- [x] Unit test: `IsExpired()` returns correct value
- [x] Unit test: Custom claims embedding works

---

### 1.4 Define Configuration Structs

**Description:** Create configuration structs in `config.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] `Config` struct with all configuration fields
- [x] Validation method `Config.Validate() error`
- [x] Default values defined
- [x] Config validation returns meaningful errors

**Implementation:**
```go
type Config struct {
    Secret               string
    AccessTokenTTL       time.Duration
    RefreshTokenTTL      time.Duration
    SigningMethod        SigningMethod
    TablePrefix          string
    AutoMigrate          bool
    CleanupInterval      time.Duration
    PermissionCheck      bool
    PermissionCacheTTL   time.Duration
    RoleSyncOnStartup    bool
    APIKeyPrefix         string
    APIKeyLength         int
}
```

**Testing:**
- [x] Unit test: Empty secret returns `ErrConfigInvalid`
- [x] Unit test: Default values are applied
- [x] Unit test: Invalid TTL values rejected

---

### 1.5 Implement Functional Options

**Description:** Create builder options in `options.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] `Option` type defined as `func(*Config)`
- [x] All `With*` functions implemented
- [x] Options can be chained
- [x] Options override defaults

**Options to implement:**
```go
WithSecret(secret string)
WithStore(store Store)
WithRBACFromFile(path string)
WithRBACFromBytes(data []byte)
WithRBACFromEnv()
WithAccessTokenTTL(ttl time.Duration)
WithRefreshTokenTTL(ttl time.Duration)
WithSigningMethod(method SigningMethod)
WithKeyPair(private, public any)
WithTablePrefix(prefix string)
WithAutoMigrate(enabled bool)
WithCleanupInterval(interval time.Duration)
WithPermissionVersionCheck(enabled bool)
WithPermissionCacheTTL(ttl time.Duration)
WithRoleSyncOnStartup(enabled bool)
WithPasswordHasher(hasher Hasher)
WithAPIKeyPrefix(prefix string)
WithAPIKeyLength(length int)
WithRateLimiter(config RateLimitConfig)
```

**Testing:**
- [x] Unit test: Each option modifies config correctly
- [x] Unit test: Options can override defaults
- [x] Unit test: Multiple options can be combined

---

### 1.6 Define Store Interface

**Description:** Create store interface in `store/store.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] `Store` interface with all required methods
- [x] Model structs in `store/models.go`
- [x] Context support for all methods
- [x] Clear documentation for each method

**Testing:**
- [x] Interface compiles without errors
- [x] Mock store can implement interface

---

### 1.7 Create Main Entry Point

**Description:** Create `Auth[T]` struct and `New[T]()` constructor in `goauth.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] `Auth[T]` struct with all required fields
- [x] `New[T]()` constructor with validation
- [x] `Close()` method for cleanup
- [x] Returns error if store not provided
- [x] Returns error if secret not provided

**Implementation:**
```go
type Auth[T Claims] struct {
    config       *Config
    store        Store
    tokenService *token.Service
    rbac         *rbac.RBAC
    apiKeyMgr    *apikey.Manager
    hasher       password.Hasher
    rateLimiter  ratelimit.Limiter
    cleanup      *cleanup.Worker
}

func New[T Claims](opts ...Option) (*Auth[T], error)
```

**Testing:**
- [x] Unit test: Returns error without store
- [x] Unit test: Returns error without secret
- [x] Unit test: Successfully creates instance with valid config
- [x] Unit test: `Close()` stops background workers

---

### 1.8 Internal Utilities

**Description:** Create internal utility functions.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] `internal/crypto/random.go`: Secure random string generation
- [x] `internal/hash/hash.go`: SHA256 hashing utilities
- [x] Functions are not exported

**Testing:**
- [x] Unit test: Random strings are unique
- [x] Unit test: Random strings have correct length
- [x] Unit test: SHA256 produces consistent results
- [x] Unit test: Constant-time comparison works

---

## Phase 1 Checklist

- [x] Project structure created
- [x] All error types defined and tested
- [x] Claims structs defined and tested
- [x] Configuration structs defined and tested
- [x] Functional options implemented and tested
- [x] Store interface defined
- [x] Main entry point created and tested
- [x] Internal utilities created and tested
- [x] All tests pass
- [x] Code linted without errors

## Dependencies

None (this is the foundation phase)

## Test Commands

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/...

# Lint
golangci-lint run
```

## Test Coverage Results

```
github.com/aloks98/goauth              92.0%
github.com/aloks98/goauth/internal/crypto  77.8%
github.com/aloks98/goauth/internal/hash    100.0%
github.com/aloks98/goauth/store           100.0%
```
