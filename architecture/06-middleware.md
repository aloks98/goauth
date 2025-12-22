# Middleware

## Overview

GoAuth provides middleware for popular Go web frameworks. The middleware handles JWT validation, permission checking, and context injection.

## Supported Frameworks

| Framework | Package | Import |
|-----------|---------|--------|
| net/http | `middleware` | `goauth/middleware` |
| Fiber | `middleware` | `goauth/middleware` |
| Echo | `middleware` | `goauth/middleware` |
| Gin | `middleware` | `goauth/middleware` |
| Chi | `middleware` | `goauth/middleware` |

## Core Functionality

All middleware implementations share the same core logic:

1. Extract token from `Authorization: Bearer <token>` header
2. Validate JWT signature and expiry
3. Check token blacklist
4. Check permission version (optional)
5. Inject claims into request context
6. Call next handler or return error

## Usage Examples

### net/http

```go
import "github.com/yourusername/goauth/middleware"

// Create middleware
authMiddleware := middleware.NewHTTP(auth)

// Apply to routes
mux := http.NewServeMux()

// Protected route
mux.Handle("/api/", authMiddleware.Authenticate(apiHandler))

// With permission check
mux.Handle("/api/admin", 
    authMiddleware.Authenticate(
        authMiddleware.RequirePermission("admin:*")(adminHandler),
    ),
)
```

### Fiber

```go
import "github.com/yourusername/goauth/middleware"

app := fiber.New()

// Create middleware
authMiddleware := middleware.NewFiber(auth)

// Protected routes
api := app.Group("/api", authMiddleware.Authenticate())

api.Get("/monitors", monitorsHandler)
api.Post("/monitors", authMiddleware.RequirePermission("monitors:write"), createMonitorHandler)
```

### Echo

```go
import "github.com/yourusername/goauth/middleware"

e := echo.New()

// Create middleware
authMiddleware := middleware.NewEcho(auth)

// Protected routes
api := e.Group("/api", authMiddleware.Authenticate())

api.GET("/monitors", monitorsHandler)
api.POST("/monitors", createMonitorHandler, authMiddleware.RequirePermission("monitors:write"))
```

### Gin

```go
import "github.com/yourusername/goauth/middleware"

r := gin.Default()

// Create middleware
authMiddleware := middleware.NewGin(auth)

// Protected routes
api := r.Group("/api", authMiddleware.Authenticate())

api.GET("/monitors", monitorsHandler)
api.POST("/monitors", authMiddleware.RequirePermission("monitors:write"), createMonitorHandler)
```

### Chi

```go
import "github.com/yourusername/goauth/middleware"

r := chi.NewRouter()

// Create middleware
authMiddleware := middleware.NewChi(auth)

// Protected routes
r.Route("/api", func(r chi.Router) {
    r.Use(authMiddleware.Authenticate())
    
    r.Get("/monitors", monitorsHandler)
    r.With(authMiddleware.RequirePermission("monitors:write")).Post("/monitors", createMonitorHandler)
})
```

## Middleware Methods

### Authenticate() ✅

Works in both modes. Validates JWT and injects claims into context.

```go
// Returns 401 if:
// - No token provided
// - Invalid token signature
// - Token expired
// - Token blacklisted
// - Permission version mismatch (RBAC mode only)
```

### RequirePermission(permission string) 🔐

**Requires RBAC mode.** Checks if user has the specified permission.

```go
authMiddleware.RequirePermission("monitors:write")

// Returns 403 if user doesn't have permission
// Returns 500 if RBAC not enabled
```

### RequirePermissions(permissions ...string) 🔐

**Requires RBAC mode.** Checks if user has ALL specified permissions.

```go
authMiddleware.RequirePermissions("users:read", "users:delete")

// Returns 403 if user doesn't have all permissions
```

### RequireAnyPermission(permissions ...string) 🔐

**Requires RBAC mode.** Checks if user has ANY of the specified permissions.

```go
authMiddleware.RequireAnyPermission("admin:*", "reports:read")

// Returns 403 if user doesn't have at least one permission
```

### AuthenticateAPIKey() ✅

Works in both modes. Validates API key instead of JWT.

```go
// API key from header: X-API-Key: sk_live_abc123...
// Or from query: ?api_key=sk_live_abc123...

api.Use(authMiddleware.AuthenticateAPIKey())
```

### Optional() ✅

Works in both modes. Validates token if present, but doesn't require it.

```go
// For routes that work differently for authenticated vs anonymous users
api.Use(authMiddleware.Optional())
```

## Accessing Claims in Handlers

### Generic Claims

```go
func handler(w http.ResponseWriter, r *http.Request) {
    claims := goauth.ClaimsFromContext[MyClaims](r.Context())
    
    userID := claims.UserID
    tenantID := claims.TenantID  // Custom field
    
    // Check permission manually
    if goauth.HasPermission(claims, "monitors:delete") {
        // Can delete
    }
}
```

### Framework-Specific

**Fiber:**
```go
func handler(c *fiber.Ctx) error {
    claims := goauth.ClaimsFromFiber[MyClaims](c)
    // ...
}
```

**Echo:**
```go
func handler(c echo.Context) error {
    claims := goauth.ClaimsFromEcho[MyClaims](c)
    // ...
}
```

**Gin:**
```go
func handler(c *gin.Context) {
    claims := goauth.ClaimsFromGin[MyClaims](c)
    // ...
}
```

## Error Responses

All middleware returns consistent JSON error responses:

```json
{
  "error": {
    "code": "TOKEN_EXPIRED",
    "message": "Token has expired"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `TOKEN_MISSING` | 401 | No token in request |
| `TOKEN_INVALID` | 401 | Invalid token format or signature |
| `TOKEN_EXPIRED` | 401 | Token has expired |
| `TOKEN_BLACKLISTED` | 401 | Token has been revoked |
| `PERMISSIONS_CHANGED` | 401 | User permissions changed, refresh required |
| `PERMISSION_DENIED` | 403 | User lacks required permission |
| `API_KEY_INVALID` | 401 | Invalid API key |
| `API_KEY_EXPIRED` | 401 | API key has expired |
| `API_KEY_REVOKED` | 401 | API key has been revoked |

## Custom Error Handler

```go
authMiddleware := middleware.NewHTTP(auth, middleware.WithErrorHandler(
    func(w http.ResponseWriter, r *http.Request, err error) {
        // Custom error handling
        w.Header().Set("Content-Type", "application/json")
        
        var status int
        var code string
        
        switch {
        case errors.Is(err, goauth.ErrTokenExpired):
            status = http.StatusUnauthorized
            code = "TOKEN_EXPIRED"
        case errors.Is(err, goauth.ErrPermissionDenied):
            status = http.StatusForbidden
            code = "PERMISSION_DENIED"
        default:
            status = http.StatusUnauthorized
            code = "UNAUTHORIZED"
        }
        
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(map[string]any{
            "error": map[string]any{
                "code":    code,
                "message": err.Error(),
            },
        })
    },
))
```

## Token Extraction

By default, middleware extracts tokens from:

1. `Authorization: Bearer <token>` header (preferred)
2. `access_token` query parameter (fallback)
3. `access_token` cookie (if enabled)

```go
// Enable cookie extraction
authMiddleware := middleware.NewHTTP(auth, 
    middleware.WithTokenFromCookie("auth_token"),
)
```

## Skip Paths

Exclude certain paths from authentication:

```go
authMiddleware := middleware.NewHTTP(auth,
    middleware.WithSkipPaths("/health", "/metrics", "/api/public/*"),
)
```
