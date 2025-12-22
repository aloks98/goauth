# Testing Strategy

## Overview

GoAuth uses a multi-layered testing approach to ensure reliability and correctness.

---

## Test Types

### 1. Unit Tests

**Purpose:** Test individual functions and methods in isolation.

**Location:** `*_test.go` files alongside source code.

**Characteristics:**
- No external dependencies
- Use memory store or mocks
- Fast execution (< 1s per test)
- Table-driven where applicable

**Example:**
```go
func TestMatchPermission(t *testing.T) {
    tests := []struct {
        name     string
        held     string
        required string
        want     bool
    }{
        {"exact match", "monitors:read", "monitors:read", true},
        {"wildcard action", "monitors:*", "monitors:read", true},
        {"wildcard resource", "*:read", "monitors:read", true},
        {"super wildcard", "*", "monitors:read", true},
        {"no match", "monitors:read", "monitors:write", false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := MatchPermission(tt.held, tt.required)
            if got != tt.want {
                t.Errorf("MatchPermission(%q, %q) = %v, want %v",
                    tt.held, tt.required, got, tt.want)
            }
        })
    }
}
```

---

### 2. Integration Tests

**Purpose:** Test components working together with real databases.

**Location:** `*_integration_test.go` files with `//go:build integration` tag.

**Characteristics:**
- Requires external services (Postgres, Redis, etc.)
- Uses Docker Compose for test environment
- Slower execution
- Tests real database behavior

**Setup:**
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
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U test"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
```

**Example:**
```go
//go:build integration

func TestPostgresStore_RefreshTokenLifecycle(t *testing.T) {
    store := setupPostgresStore(t)
    defer store.Close()
    
    ctx := context.Background()
    
    // Create token
    token := &RefreshToken{
        ID:        uuid.New().String(),
        UserID:    "user1",
        FamilyID:  uuid.New().String(),
        TokenHash: "hash123",
        IssuedAt:  time.Now(),
        ExpiresAt: time.Now().Add(24 * time.Hour),
    }
    
    err := store.SaveRefreshToken(ctx, token)
    require.NoError(t, err)
    
    // Retrieve token
    retrieved, err := store.GetRefreshToken(ctx, token.ID)
    require.NoError(t, err)
    require.Equal(t, token.UserID, retrieved.UserID)
    
    // Revoke token
    err = store.RevokeRefreshToken(ctx, token.ID, "newtoken123")
    require.NoError(t, err)
    
    // Verify revoked
    retrieved, err = store.GetRefreshToken(ctx, token.ID)
    require.NoError(t, err)
    require.NotNil(t, retrieved.RevokedAt)
}
```

---

### 3. End-to-End Tests

**Purpose:** Test complete user flows through the API.

**Characteristics:**
- Tests full authentication flows
- Uses HTTP test servers
- Validates response formats

**Example:**
```go
func TestE2E_LoginRefreshLogout(t *testing.T) {
    auth := setupFullAuth(t)
    mw := middleware.NewHTTP(auth)
    
    // Setup test server
    mux := http.NewServeMux()
    mux.Handle("/protected", mw.Authenticate(protectedHandler))
    server := httptest.NewServer(mux)
    defer server.Close()
    
    // 1. Generate tokens (simulating login)
    tokens, err := auth.GenerateTokenPair(ctx, "user1", TestClaims{})
    require.NoError(t, err)
    
    // 2. Access protected resource
    req, _ := http.NewRequest("GET", server.URL+"/protected", nil)
    req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    require.Equal(t, 200, resp.StatusCode)
    
    // 3. Refresh tokens
    newTokens, err := auth.RefreshTokens(ctx, tokens.RefreshToken)
    require.NoError(t, err)
    
    // 4. Old access token still works (not blacklisted)
    // 5. Logout (revoke tokens)
    err = auth.RevokeAllUserTokens(ctx, "user1")
    require.NoError(t, err)
    
    // 6. Access denied
    resp, _ = http.DefaultClient.Do(req)
    require.Equal(t, 401, resp.StatusCode)
}
```

---

### 4. Benchmark Tests

**Purpose:** Measure performance of critical operations.

**Location:** `*_bench_test.go` files.

**Example:**
```go
func BenchmarkJWTGeneration(b *testing.B) {
    service := setupTokenService(b)
    claims := TestClaims{UserID: "user1"}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := service.GenerateAccessToken(claims)
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkArgon2Hash(b *testing.B) {
    hasher := password.NewArgon2(password.DefaultConfig)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := hasher.Hash("password123")
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

---

## Test Helpers

### Common Test Utilities

```go
// testutil/auth.go
package testutil

func SetupTestAuth(t *testing.T) *goauth.Auth[TestClaims] {
    t.Helper()
    
    store := memory.New()
    auth, err := goauth.New[TestClaims](
        goauth.WithSecret("test-secret-key-32-bytes-long!!"),
        goauth.WithStore(store),
        goauth.WithRBACFromBytes(testPermissionsYAML),
    )
    require.NoError(t, err)
    
    t.Cleanup(func() {
        auth.Close()
    })
    
    return auth
}

type TestClaims struct {
    goauth.StandardClaims
    TenantID string `json:"tenant_id"`
}
```

---

## Running Tests

```bash
# All unit tests
go test ./...

# With verbose output
go test ./... -v

# Specific package
go test ./token/... -v

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Integration tests
docker-compose -f docker-compose.test.yml up -d
go test ./... -tags=integration -v
docker-compose -f docker-compose.test.yml down

# Benchmarks
go test ./... -bench=. -benchmem

# Race detection
go test ./... -race

# Short tests only (skip slow tests)
go test ./... -short
```

---

## CI/CD Pipeline

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - run: go test ./... -race -coverprofile=coverage.out
      - uses: codecov/codecov-action@v3
        with:
          files: coverage.out

  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: goauth_test
        ports:
          - 5432:5432
      redis:
        image: redis:7
        ports:
          - 6379:6379
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - run: go test ./... -tags=integration -v
```

---

## Coverage Targets

| Package | Minimum | Target |
|---------|---------|--------|
| goauth | 75% | 85% |
| token | 80% | 90% |
| password | 85% | 95% |
| apikey | 80% | 90% |
| rbac | 80% | 90% |
| store/* | 75% | 85% |
| middleware | 75% | 85% |

---

## Test Data

### Sample Permissions Config

```yaml
# testdata/permissions.yaml
version: 1

permission_groups:
  - key: monitors
    name: Monitors
    permissions:
      - key: monitors:read
        name: View monitors
      - key: monitors:write
        name: Edit monitors

role_templates:
  - key: viewer
    name: Viewer
    permissions: [monitors:read]
  - key: editor
    name: Editor
    permissions: [monitors:read, monitors:write]
  - key: admin
    name: Admin
    permissions: [monitors:*]
```
