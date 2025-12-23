# Phase 5: Store Implementations

**Duration:** 4-5 days
**Goal:** Implement database stores for PostgreSQL, MySQL, and Memory.

**Note:** Redis is used for rate limiting (`ratelimit/redis.go`) but not as a token/permission store.

**Dependencies:** Phase 1 (Foundation - Store Interface)

---

## Tasks

### 5.1 Store Models

**Description:** Define shared data models in `store/models.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] All model structs with proper tags
- [x] DB tags for SQL mapping
- [x] JSON tags for serialization
- [x] Helper methods for common operations

**Models:**
```go
type RefreshToken struct {
    ID         string     `db:"id" json:"id"`
    UserID     string     `db:"user_id" json:"user_id"`
    FamilyID   string     `db:"family_id" json:"family_id"`
    TokenHash  string     `db:"token_hash" json:"token_hash"`
    IssuedAt   time.Time  `db:"issued_at" json:"issued_at"`
    ExpiresAt  time.Time  `db:"expires_at" json:"expires_at"`
    RevokedAt  *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
    ReplacedBy *string    `db:"replaced_by" json:"replaced_by,omitempty"`
}

type BlacklistEntry struct {
    JTI       string    `db:"jti" json:"jti"`
    ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
}

type UserPermissions struct {
    UserID            string    `db:"user_id" json:"user_id"`
    RoleLabel         string    `db:"role_label" json:"role_label"`
    BaseRole          string    `db:"base_role" json:"base_role"`
    Permissions       []string  `db:"permissions" json:"permissions"`
    PermissionVersion int       `db:"permission_version" json:"permission_version"`
    UpdatedAt         time.Time `db:"updated_at" json:"updated_at"`
    UpdatedBy         *string   `db:"updated_by" json:"updated_by,omitempty"`
}

type StoredRoleTemplate struct {
    RoleKey         string    `db:"role_key" json:"role_key"`
    Name            string    `db:"name" json:"name"`
    Description     string    `db:"description" json:"description"`
    Permissions     []string  `db:"permissions" json:"permissions"`
    PermissionsHash string    `db:"permissions_hash" json:"permissions_hash"`
    UpdatedAt       time.Time `db:"updated_at" json:"updated_at"`
}

type RoleSyncLog struct {
    ID             string    `db:"id" json:"id"`
    RoleKey        string    `db:"role_key" json:"role_key"`
    OldPermissions []string  `db:"old_permissions" json:"old_permissions"`
    NewPermissions []string  `db:"new_permissions" json:"new_permissions"`
    UsersAffected  int64     `db:"users_affected" json:"users_affected"`
    SyncedAt       time.Time `db:"synced_at" json:"synced_at"`
}

type APIKey struct {
    ID         string     `db:"id" json:"id"`
    UserID     string     `db:"user_id" json:"user_id"`
    Prefix     string     `db:"prefix" json:"prefix"`
    KeyHash    string     `db:"key_hash" json:"key_hash"`
    Name       string     `db:"name" json:"name"`
    Scopes     []string   `db:"scopes" json:"scopes"`
    LastUsedAt *time.Time `db:"last_used_at" json:"last_used_at,omitempty"`
    ExpiresAt  *time.Time `db:"expires_at" json:"expires_at,omitempty"`
    CreatedAt  time.Time  `db:"created_at" json:"created_at"`
    RevokedAt  *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
}
```

**Testing:**
- [x] Unit test: Model serialization works

---

### 5.2 Memory Store

**Description:** Implement in-memory store for testing in `store/memory/memory.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [x] Implements full Store interface
- [x] Uses maps with mutex for thread safety
- [x] Simulates all operations
- [x] Useful for unit testing other packages

**Implementation:**
```go
type MemoryStore struct {
    refreshTokens   map[string]*RefreshToken
    blacklist       map[string]*BlacklistEntry
    userPermissions map[string]*UserPermissions
    roleTemplates   map[string]*StoredRoleTemplate
    apiKeys         map[string]*APIKey
    syncLogs        []*RoleSyncLog
    mu              sync.RWMutex
}

func New() *MemoryStore
```

**Testing:**
- [x] Unit test: All interface methods work
- [x] Unit test: Thread-safe concurrent access
- [x] Unit test: Cleanup removes expired entries

---

### 5.3 SQL Store Base

**Description:** Implement common SQL functionality in `store/sql/sql.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [x] Generic SQL implementation
- [x] Prepared statements for all queries
- [x] Dialect abstraction for differences
- [x] Connection pooling configuration
- [x] Context support with timeouts

**Implementation:**
```go
type SQLStore struct {
    db          *sql.DB
    dialect     Dialect
    tablePrefix string
}

type Config struct {
    DSN         string
    TablePrefix string
    MaxConns    int
    MaxIdleTime time.Duration
}

type Dialect interface {
    ArrayType() string
    Placeholder(n int) string
    ArrayPlaceholder(n int) string
    UpsertQuery(table string, columns []string) string
    TimestampType() string
}
```

**Testing:**
- [x] Unit test: Query building works
- [x] Unit test: Placeholder numbering correct

---

### 5.4 SQL Migrations

**Description:** Implement auto-migration in `store/sql/migrations.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [x] Create all tables if not exist
- [x] Create all indexes
- [x] Support table prefix
- [x] Dialect-specific SQL

**Implementation:**
```go
func (s *SQLStore) Migrate(ctx context.Context) error

// Tables to create:
// - {prefix}auth_refresh_tokens
// - {prefix}auth_token_blacklist
// - {prefix}auth_user_permissions
// - {prefix}auth_role_templates
// - {prefix}auth_role_sync_log
// - {prefix}auth_api_keys
```

**Testing:**
- [ ] Integration test: Migration creates tables
- [ ] Integration test: Migration is idempotent
- [x] Integration test: Prefix is applied

---

### 5.5 PostgreSQL Store

**Description:** Implement PostgreSQL-specific store in `store/sql/postgres.go`.

**Estimated Hours:** 5

**Acceptance Criteria:**
- [x] PostgreSQL dialect implementation
- [x] Native TEXT[] for arrays
- [x] TIMESTAMP WITH TIME ZONE for times
- [x] $1, $2 placeholder style
- [x] Use pgx driver

**Implementation:**
```go
type PostgresDialect struct{}

func NewPostgres(config Config) (*SQLStore, error)
```

**Testing:**
- [ ] Integration test: All CRUD operations (requires Postgres)
- [ ] Integration test: Array operations work
- [ ] Integration test: Timestamps are correct timezone
- [ ] Integration test: Concurrent operations safe

---

### 5.6 MySQL Store

**Description:** Implement MySQL-specific store in `store/sql/mysql.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [x] MySQL dialect implementation
- [x] JSON type for arrays
- [x] DATETIME for times
- [x] ? placeholder style
- [x] Use go-sql-driver/mysql

**Implementation:**
```go
type MySQLDialect struct{}

func NewMySQL(config Config) (*SQLStore, error)
```

**Testing:**
- [ ] Integration test: All CRUD operations (requires MySQL)
- [ ] Integration test: JSON arrays work
- [ ] Integration test: Concurrent operations safe

---

### 5.7 Store Factory

**Description:** Create factory functions for easy store creation.

**Estimated Hours:** 1

**Acceptance Criteria:**
- [ ] Convenience functions for each store type
- [ ] Common configuration handling
- [ ] Clear error messages

**Implementation:**
```go
// In store/store.go
func Postgres(dsn string, opts ...Option) (Store, error)
func MySQL(dsn string, opts ...Option) (Store, error)
func Memory() Store
```

**Testing:**
- [ ] Unit test: Factory creates correct store type

---

## Remaining Work

> **STATUS: ✅ 95% Complete** - Memory and SQL (PostgreSQL, MySQL) stores are fully implemented. Only integration tests with Docker remain.

- [ ] Docker compose integration tests
- [ ] Factory functions for convenient store creation (optional)

---

## Phase 5 Checklist

- [x] Store models defined
- [x] Memory store implemented and tested
- [x] SQL base implemented
- [x] Migrations implemented
- [x] PostgreSQL store implemented and tested
- [x] MySQL store implemented and tested
- [ ] Factory functions created (optional)
- [x] All unit tests pass
- [ ] All integration tests pass

## Integration Test Setup

### Docker Compose for Testing

```yaml
# docker-compose.test.yml
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: test
      POSTGRES_PASSWORD: test
      POSTGRES_DB: goauth_test
    ports:
      - "5432:5432"

  mysql:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: test
      MYSQL_DATABASE: goauth_test
    ports:
      - "3306:3306"
```

### Running Integration Tests

```bash
# Start test databases
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
go test ./store/... -tags=integration -v

# Run specific store tests
go test ./store/sql/... -tags=integration -run TestPostgres
go test ./store/sql/... -tags=integration -run TestMySQL

# Stop test databases
docker-compose -f docker-compose.test.yml down
```

## Test Scenarios

```go
// Build tag: integration

func TestStore_RefreshTokenLifecycle(t *testing.T) {
    // For each store type:
    // 1. Save refresh token
    // 2. Get refresh token
    // 3. Revoke refresh token
    // 4. Verify revoked
    // 5. Delete expired
}

func TestStore_UserPermissions(t *testing.T) {
    // 1. Save permissions
    // 2. Get permissions
    // 3. Update permissions
    // 4. Verify version bumped
}

func TestStore_RoleSync(t *testing.T) {
    // 1. Save role template
    // 2. Update users with role
    // 3. Verify users updated
    // 4. Log sync audit
}

func TestStore_Concurrent(t *testing.T) {
    // 1. Spawn multiple goroutines
    // 2. Concurrent reads/writes
    // 3. Verify no race conditions
}
```
