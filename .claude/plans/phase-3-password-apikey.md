# Phase 3: Password Hashing & API Keys

**Duration:** 3-4 days
**Goal:** Implement password hashing and API key management.

**Dependencies:** Phase 1 (Foundation)

---

## Tasks

### 3.1 Password Hasher Interface

**Description:** Define hasher interface in `password/hasher.go`.

**Estimated Hours:** 1

**Acceptance Criteria:**
- [ ] `Hasher` interface with `Hash()` and `Verify()` methods
- [ ] `NeedsRehash()` method for algorithm upgrades
- [ ] Clear documentation

**Implementation:**
```go
type Hasher interface {
    Hash(password string) (string, error)
    Verify(password, hash string) (bool, error)
    NeedsRehash(hash string) bool
}
```

**Testing:**
- [ ] Interface compiles without errors

---

### 3.2 Argon2id Implementation

**Description:** Implement Argon2id hasher in `password/argon2.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [ ] Configurable memory, iterations, parallelism
- [ ] Default configuration follows OWASP recommendations
- [ ] Generate random salt per hash
- [ ] Encode hash in PHC format
- [ ] Parse PHC format for verification
- [ ] Constant-time comparison

**Implementation:**
```go
type Argon2Config struct {
    Memory      uint32 // Default: 64 * 1024 (64 MB)
    Iterations  uint32 // Default: 3
    Parallelism uint8  // Default: 2
    SaltLength  uint32 // Default: 16
    KeyLength   uint32 // Default: 32
}

func NewArgon2(config Argon2Config) Hasher
```

**Hash Format (PHC):**
```
$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
```

**Testing:**
- [ ] Unit test: Hash produces valid format
- [ ] Unit test: Different passwords produce different hashes
- [ ] Unit test: Same password with different salt produces different hashes
- [ ] Unit test: Verify returns true for correct password
- [ ] Unit test: Verify returns false for incorrect password
- [ ] Unit test: NeedsRehash detects outdated parameters
- [ ] Benchmark: Hash time is reasonable (100-500ms)

---

### 3.3 Bcrypt Implementation

**Description:** Implement Bcrypt hasher in `password/bcrypt.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [ ] Configurable cost factor
- [ ] Default cost follows recommendations (12)
- [ ] Use Go's `golang.org/x/crypto/bcrypt` package
- [ ] Detect bcrypt hashes for migration support

**Implementation:**
```go
type BcryptConfig struct {
    Cost int // Default: 12
}

func NewBcrypt(config BcryptConfig) Hasher
```

**Testing:**
- [ ] Unit test: Hash produces valid bcrypt format
- [ ] Unit test: Verify works correctly
- [ ] Unit test: NeedsRehash detects old cost factors
- [ ] Unit test: Cost limits are enforced

---

### 3.4 API Key Format

**Description:** Implement API key format utilities in `apikey/format.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [ ] Key format: `{prefix}_{random}`
- [ ] Configurable prefix (default or custom)
- [ ] Generate random prefix if not provided
- [ ] Parse key to extract prefix and secret
- [ ] Validate key format

**Implementation:**
```go
type KeyParts struct {
    Prefix string
    Secret string
}

func GenerateKey(prefix string, length int) (key string, parts KeyParts, err error)
func ParseKey(key string) (KeyParts, error)
func ValidateKeyFormat(key string) error
```

**Examples:**
```
sk_live_a3Bf9xK2mN7pQ4rS...
mon_8hYt2wXz5vB1nM3k...
api_test_x9Zq1wE4rT7uY2iO...
```

**Testing:**
- [ ] Unit test: Generated key has correct format
- [ ] Unit test: Parse extracts prefix and secret correctly
- [ ] Unit test: Invalid format returns error
- [ ] Unit test: Random prefix is generated when not provided
- [ ] Unit test: Key has sufficient entropy

---

### 3.5 API Key Manager

**Description:** Implement API key manager in `apikey/manager.go`.

**Estimated Hours:** 5

**Acceptance Criteria:**
- [ ] Generate new API key with options
- [ ] Store key hash (not raw key)
- [ ] Validate API key
- [ ] Support scoped keys (limited permissions)
- [ ] Track last used timestamp
- [ ] Support key expiration
- [ ] Revoke keys

**Implementation:**
```go
type Manager struct {
    store  Store
    config Config
}

type APIKeyOptions struct {
    Name      string
    Prefix    string        // Optional, uses default if empty
    Scopes    []string      // Optional, all permissions if empty
    ExpiresIn time.Duration // Optional, never expires if zero
}

type GeneratedAPIKey struct {
    ID     string // UUID for management
    Key    string // Full key (show once)
    Prefix string
    Name   string
}

func (m *Manager) Generate(ctx context.Context, userID string, opts APIKeyOptions) (*GeneratedAPIKey, error)
func (m *Manager) Validate(ctx context.Context, key string) (*APIKeyInfo, error)
func (m *Manager) Revoke(ctx context.Context, keyID string) error
func (m *Manager) List(ctx context.Context, userID string) ([]*APIKeyInfo, error)
```

**Testing:**
- [ ] Unit test: Generate returns key and ID
- [ ] Unit test: Generated key is only returned once
- [ ] Unit test: Key hash is stored, not raw key
- [ ] Unit test: Validate returns key info for valid key
- [ ] Unit test: Validate returns error for invalid key
- [ ] Unit test: Expired key returns `ErrAPIKeyExpired`
- [ ] Unit test: Revoked key returns `ErrAPIKeyRevoked`
- [ ] Unit test: Last used is updated on validation
- [ ] Unit test: Scoped keys have correct permissions
- [ ] Integration test: Full lifecycle

---

### 3.6 API Key Scopes

**Description:** Implement scope checking for API keys.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [ ] API key can have limited scopes
- [ ] Scope is checked against required permission
- [ ] Empty scopes = all user's permissions
- [ ] Scope uses same wildcard matching as RBAC

**Implementation:**
```go
type APIKeyInfo struct {
    ID          string
    UserID      string
    Prefix      string
    Name        string
    Scopes      []string // Empty = all permissions
    LastUsedAt  *time.Time
    ExpiresAt   *time.Time
    CreatedAt   time.Time
}

func (m *Manager) HasScope(info *APIKeyInfo, required string) bool
```

**Testing:**
- [ ] Unit test: Key with scopes only allows listed permissions
- [ ] Unit test: Key without scopes allows all
- [ ] Unit test: Wildcard scopes work (`monitors:*`)

---

### 3.7 Wire Up to Auth

**Description:** Connect password and API key to main Auth struct.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [ ] `auth.HashPassword()` uses configured hasher
- [ ] `auth.VerifyPassword()` uses configured hasher
- [ ] `auth.GenerateAPIKey()` uses manager
- [ ] `auth.ValidateAPIKey()` uses manager
- [ ] `auth.RevokeAPIKey()` uses manager
- [ ] `auth.GetUserAPIKeys()` uses manager

**Testing:**
- [ ] Unit test: All methods delegate correctly
- [ ] Integration test: Full password flow
- [ ] Integration test: Full API key flow

---

## Phase 3 Checklist

- [ ] Hasher interface defined
- [ ] Argon2id implementation complete and tested
- [ ] Bcrypt implementation complete and tested
- [ ] API key format utilities complete and tested
- [ ] API key manager complete and tested
- [ ] API key scopes implemented and tested
- [ ] Auth struct wired up and tested
- [ ] All unit tests pass
- [ ] Integration tests pass

## Security Considerations

### Password Hashing

1. **Never store plain passwords**
2. **Use Argon2id** for new applications
3. **Bcrypt for compatibility** with legacy systems
4. **Migrate on verify**: Check `NeedsRehash()` and rehash on login

### API Keys

1. **Show key only once**: Never retrieve raw key from DB
2. **Store hash only**: SHA256 of the secret part
3. **Use secure random**: `crypto/rand` for key generation
4. **Prefix for identification**: Allows quick lookup without exposing key
5. **Scope limitation**: Minimum permissions needed

## Test Commands

```bash
# Run password package tests
go test ./password/... -v

# Run API key package tests
go test ./apikey/... -v

# Run benchmarks
go test ./password/... -bench=.

# Run with race detection
go test ./password/... ./apikey/... -race
```

## Benchmark Targets

| Operation | Target Time |
|-----------|-------------|
| Argon2id Hash | 100-500ms |
| Argon2id Verify | 100-500ms |
| Bcrypt Hash (cost 12) | 200-400ms |
| API Key Validate | < 10ms |
