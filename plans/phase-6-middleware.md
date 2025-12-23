# Phase 6: Middleware

**Duration:** 4-5 days
**Goal:** Implement authentication middleware for multiple web frameworks.

**Dependencies:** Phase 2 (Token Service), Phase 4 (RBAC)

---

## Tasks

### 6.1 Core Middleware Logic

**Description:** Implement framework-agnostic middleware logic in `middleware/middleware.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [x] Token extraction from header/query/cookie
- [x] JWT validation delegation to token service
- [x] Blacklist checking
- [x] Permission version checking
- [x] Claims context injection
- [x] Error response formatting
- [x] Configurable behavior

**Implementation:**
```go
type Config struct {
    TokenService     TokenService
    RBAC             *rbac.RBAC
    SkipPaths        []string
    TokenLookup      []TokenLookupSource
    ErrorHandler     ErrorHandler
    SuccessHandler   SuccessHandler
}

type TokenLookupSource struct {
    Type string // "header", "query", "cookie"
    Name string // "Authorization", "access_token", etc.
}

type Core struct {
    config Config
}

func NewCore(config Config) *Core

func (c *Core) Authenticate(token string) (*Claims, error)
func (c *Core) ExtractToken(sources []TokenLookupSource, getter TokenGetter) (string, error)
func (c *Core) CheckPermission(permissions []string, required string) bool
func (c *Core) ShouldSkip(path string) bool
```

**Testing:**
- [x] Unit test: Token extraction from header
- [x] Unit test: Token extraction from query
- [x] Unit test: Token extraction from cookie
- [x] Unit test: Path skipping works
- [x] Unit test: Permission checking delegates correctly

---

### 6.2 Context Helpers

**Description:** Implement context key and helpers for claims storage.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] Context key for claims storage
- [x] Generic `ClaimsFromContext[T]()` function
- [x] Safe nil handling
- [x] Framework-specific adapters

**Implementation:**
```go
type contextKey string

const claimsContextKey contextKey = "goauth_claims"

func ContextWithClaims(ctx context.Context, claims any) context.Context
func ClaimsFromContext[T Claims](ctx context.Context) *T
```

**Testing:**
- [x] Unit test: Claims stored and retrieved correctly
- [x] Unit test: Missing claims returns nil
- [x] Unit test: Type assertion works

---

### 6.3 net/http Middleware

**Description:** Implement standard library middleware in `middleware/http.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] `Authenticate()` middleware function
- [x] `RequirePermission()` middleware
- [x] `RequirePermissions()` middleware
- [x] `RequireAnyPermission()` middleware
- [x] `AuthenticateAPIKey()` middleware
- [x] `Optional()` middleware
- [x] Standard error responses

**Implementation:**
```go
type HTTPMiddleware struct {
    core *Core
}

func NewHTTP(auth *Auth, opts ...Option) *HTTPMiddleware

func (m *HTTPMiddleware) Authenticate(next http.Handler) http.Handler
func (m *HTTPMiddleware) RequirePermission(perm string) func(http.Handler) http.Handler
func (m *HTTPMiddleware) RequirePermissions(perms ...string) func(http.Handler) http.Handler
func (m *HTTPMiddleware) RequireAnyPermission(perms ...string) func(http.Handler) http.Handler
func (m *HTTPMiddleware) AuthenticateAPIKey(next http.Handler) http.Handler
func (m *HTTPMiddleware) Optional(next http.Handler) http.Handler
```

**Testing:**
- [x] Unit test: Authenticate passes valid token
- [x] Unit test: Authenticate rejects invalid token
- [x] Unit test: RequirePermission checks permission
- [x] Unit test: Optional allows missing token
- [ ] Integration test: Full HTTP flow

---

### 6.4 Fiber Middleware

**Description:** Implement Fiber framework middleware in `middleware/fiber.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] Same functionality as HTTP middleware
- [x] Uses Fiber context
- [x] Fiber-style handler signature
- [x] Helper: `ClaimsFromFiber[T](c *fiber.Ctx)`

**Implementation:**
```go
type FiberMiddleware struct {
    core *Core
}

func NewFiber(auth *Auth, opts ...Option) *FiberMiddleware

func (m *FiberMiddleware) Authenticate() fiber.Handler
func (m *FiberMiddleware) RequirePermission(perm string) fiber.Handler
func (m *FiberMiddleware) RequirePermissions(perms ...string) fiber.Handler
func (m *FiberMiddleware) RequireAnyPermission(perms ...string) fiber.Handler
func (m *FiberMiddleware) AuthenticateAPIKey() fiber.Handler
func (m *FiberMiddleware) Optional() fiber.Handler

func ClaimsFromFiber[T Claims](c *fiber.Ctx) *T
```

**Testing:**
- [x] Unit test: All middleware functions work
- [ ] Integration test: Full Fiber app flow

---

### 6.5 Echo Middleware

**Description:** Implement Echo framework middleware in `middleware/echo.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] Same functionality as HTTP middleware
- [x] Uses Echo context
- [x] Echo-style handler signature
- [x] Helper: `ClaimsFromEcho[T](c echo.Context)`

**Implementation:**
```go
type EchoMiddleware struct {
    core *Core
}

func NewEcho(auth *Auth, opts ...Option) *EchoMiddleware

func (m *EchoMiddleware) Authenticate() echo.MiddlewareFunc
func (m *EchoMiddleware) RequirePermission(perm string) echo.MiddlewareFunc
// ... similar to HTTP

func ClaimsFromEcho[T Claims](c echo.Context) *T
```

**Testing:**
- [x] Unit test: All middleware functions work
- [ ] Integration test: Full Echo app flow

---

### 6.6 Gin Middleware

**Description:** Implement Gin framework middleware in `middleware/gin.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] Same functionality as HTTP middleware
- [x] Uses Gin context
- [x] Gin-style handler signature
- [x] Helper: `ClaimsFromGin[T](c *gin.Context)`

**Implementation:**
```go
type GinMiddleware struct {
    core *Core
}

func NewGin(auth *Auth, opts ...Option) *GinMiddleware

func (m *GinMiddleware) Authenticate() gin.HandlerFunc
func (m *GinMiddleware) RequirePermission(perm string) gin.HandlerFunc
// ... similar to HTTP

func ClaimsFromGin[T Claims](c *gin.Context) *T
```

**Testing:**
- [x] Unit test: All middleware functions work
- [ ] Integration test: Full Gin app flow

---

### 6.7 Chi Middleware

**Description:** Implement Chi router middleware in `middleware/chi.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] Same functionality as HTTP middleware
- [x] Compatible with Chi router
- [x] Chi-style middleware signature
- [x] Uses standard context

**Implementation:**
```go
type ChiMiddleware struct {
    core *Core
}

func NewChi(auth *Auth, opts ...Option) *ChiMiddleware

// Chi uses standard http.Handler, so methods match HTTPMiddleware
func (m *ChiMiddleware) Authenticate(next http.Handler) http.Handler
// ... similar to HTTP
```

**Testing:**
- [x] Unit test: All middleware functions work
- [ ] Integration test: Full Chi app flow

---

### 6.8 Error Response Handling

**Description:** Implement consistent error responses.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] JSON error response format
- [x] Error code mapping
- [x] Custom error handler support
- [x] Content-Type header set

**Implementation:**
```go
type ErrorResponse struct {
    Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}

type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error)

var errorCodeMap = map[error]string{
    ErrTokenExpired:       "TOKEN_EXPIRED",
    ErrTokenInvalidSig:    "TOKEN_INVALID",
    ErrTokenBlacklisted:   "TOKEN_BLACKLISTED",
    ErrPermissionsChanged: "PERMISSIONS_CHANGED",
    ErrPermissionDenied:   "PERMISSION_DENIED",
    ErrAPIKeyInvalid:      "API_KEY_INVALID",
    // ...
}
```

**Testing:**
- [x] Unit test: Error code mapping correct
- [x] Unit test: JSON response format correct
- [x] Unit test: Custom handler is called

---

### 6.9 Middleware Options

**Description:** Implement middleware configuration options.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] Skip paths configuration
- [x] Custom token lookup sources
- [x] Custom error handler
- [x] Token from cookie option

**Implementation:**
```go
type Option func(*Config)

func WithSkipPaths(paths ...string) Option
func WithTokenFromHeader(name string) Option
func WithTokenFromQuery(name string) Option
func WithTokenFromCookie(name string) Option
func WithErrorHandler(handler ErrorHandler) Option
```

**Testing:**
- [x] Unit test: Options modify config correctly
- [x] Unit test: Skip paths work
- [x] Unit test: Custom token sources work

---

## Remaining Work

> **STATUS: ~95% Complete** - All middleware adapters implemented with tests. Only need full integration tests.

- [ ] Full integration tests for each framework

---

## Phase 6 Checklist

- [x] Core middleware logic implemented
- [x] Context helpers implemented
- [x] net/http middleware implemented and tested
- [x] Fiber middleware implemented and tested
- [x] Echo middleware implemented and tested
- [x] Gin middleware implemented and tested
- [x] Chi middleware implemented and tested
- [x] Error handling implemented
- [x] Middleware options implemented
- [x] All unit tests pass
- [ ] All integration tests pass

## Integration Test Examples

### net/http

```go
func TestHTTPMiddleware_Integration(t *testing.T) {
    auth := setupTestAuth(t)
    mw := middleware.NewHTTP(auth)
    
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := goauth.ClaimsFromContext[TestClaims](r.Context())
        w.Write([]byte(claims.UserID))
    })
    
    server := httptest.NewServer(mw.Authenticate(handler))
    defer server.Close()
    
    // Test with valid token
    tokens, _ := auth.GenerateTokenPair(ctx, "user1", TestClaims{})
    req, _ := http.NewRequest("GET", server.URL, nil)
    req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
    
    resp, _ := http.DefaultClient.Do(req)
    // Assert 200 and body
    
    // Test without token
    req, _ = http.NewRequest("GET", server.URL, nil)
    resp, _ = http.DefaultClient.Do(req)
    // Assert 401
}
```

### Fiber

```go
func TestFiberMiddleware_Integration(t *testing.T) {
    auth := setupTestAuth(t)
    mw := middleware.NewFiber(auth)
    
    app := fiber.New()
    app.Use(mw.Authenticate())
    app.Get("/", func(c *fiber.Ctx) error {
        claims := goauth.ClaimsFromFiber[TestClaims](c)
        return c.SendString(claims.UserID)
    })
    
    // Test with valid token
    tokens, _ := auth.GenerateTokenPair(ctx, "user1", TestClaims{})
    req := httptest.NewRequest("GET", "/", nil)
    req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
    
    resp, _ := app.Test(req)
    // Assert 200
}
```

## Test Commands

```bash
# Run middleware tests
go test ./middleware/... -v

# Run with specific framework
go test ./middleware/... -run TestHTTP
go test ./middleware/... -run TestFiber
go test ./middleware/... -run TestEcho
go test ./middleware/... -run TestGin
go test ./middleware/... -run TestChi

# Run integration tests
go test ./middleware/... -tags=integration
```
