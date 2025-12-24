# GoAuth Full-Stack Demo

A complete full-stack application demonstrating all GoAuth features with HTMX + Go templates for UI and shared business logic across 5 web frameworks.

## Features Demonstrated

- **JWT Authentication**: Token generation, validation, refresh, and revocation
- **RBAC (Role-Based Access Control)**: Role assignment, permission management
- **API Keys**: Create, list, revoke API keys with scopes
- **Multiple Web Frameworks**: Same app running on Gin, Chi, Echo, Fiber, and net/http
- **HTMX UI**: Interactive UI with partial page updates

## Quick Start

### Prerequisites

1. **PostgreSQL**: The app uses the existing test database
   ```
   Host: localhost:15432
   Database: goauth_test
   User: goauth
   Password: goauth
   ```

2. **Go 1.21+**

### Running the Demo

Choose any web framework backend:

```bash
# Run with net/http (default)
make http

# Run with Gin
make gin

# Run with Chi
make chi

# Run with Echo
make echo

# Run with Fiber
make fiber
```

Then open http://localhost:8080 in your browser.

### Demo Users

| Email | Password | Role |
|-------|----------|------|
| admin@example.com | admin123 | admin (full access) |
| user@example.com | user123 | user (limited access) |
| viewer@example.com | viewer123 | viewer (read-only) |

## Project Structure

```
fullstack/
├── cmd/
│   ├── http/main.go      # net/http backend
│   ├── gin/main.go       # Gin backend
│   ├── chi/main.go       # Chi backend
│   ├── echo/main.go      # Echo backend
│   └── fiber/main.go     # Fiber backend
│
├── internal/
│   ├── app/              # Core application
│   │   ├── app.go        # App container, goauth setup
│   │   ├── config.go     # Configuration
│   │   ├── claims.go     # Custom JWT claims
│   │   └── adapter.go    # Middleware interface adapter
│   │
│   ├── handlers/         # Framework-agnostic handlers
│   │   ├── handlers.go   # Context interface
│   │   ├── auth.go       # Login, register, logout
│   │   ├── dashboard.go  # Dashboard page
│   │   ├── apikeys.go    # API key management
│   │   ├── rbac.go       # RBAC demo
│   │   └── admin.go      # Admin panel
│   │
│   ├── users/            # User store (in-memory)
│   │   ├── models.go
│   │   └── store.go
│   │
│   └── htmx/             # HTMX helpers
│       └── response.go
│
├── templates/            # Go templates
│   ├── layouts/
│   ├── pages/
│   └── partials/
│
├── static/               # Static files
│   ├── css/style.css
│   └── js/htmx.min.js
│
├── permissions.yaml      # RBAC configuration
├── Makefile
└── README.md
```

## Architecture

### Framework-Agnostic Handlers

All business logic lives in the `handlers` package using a common `Context` interface:

```go
type Context interface {
    Context() context.Context
    UserID() string
    FormValue(key string) string
    Param(key string) string
    SetCookie(cookie *http.Cookie)
    Redirect(url string, code int) error
    Render(name string, data interface{}) error
    RenderPartial(name string, data interface{}) error
    JSON(code int, data interface{}) error
    IsHTMX() bool
    HXRedirect(url string)
}
```

Each framework implements this interface, making the handlers work with any backend.

### HTMX Patterns

The UI uses HTMX for interactive updates:

- `hx-post` / `hx-get` for form submissions
- `hx-target` + `hx-swap` for partial updates
- `HX-Redirect` header for navigation after actions
- `HX-Trigger` for events (e.g., refresh API key list)

## GoAuth Features Used

| Feature | Location |
|---------|----------|
| `GenerateTokenPair` | Login handler |
| `ValidateAccessToken` | Auth middleware |
| `RefreshTokens` | Refresh endpoint |
| `RevokeAccessToken` | Logout handler |
| `RevokeAllUserTokens` | Admin panel |
| `AssignRole` | RBAC page |
| `HasPermission` | Permission checks |
| `AddPermissions` | RBAC page |
| `RemovePermissions` | RBAC page |
| `CreateAPIKey` | API Keys page |
| `ValidateAPIKey` | API auth middleware |
| `ListAPIKeys` | API Keys page |
| `RevokeAPIKey` | API Keys page |

## Pages

### Login (`/login`)
Email/password authentication form.

### Register (`/register`)
Create new account with automatic "user" role assignment.

### Dashboard (`/dashboard`)
User information, current role, and permissions list.

### API Keys (`/api-keys`)
- View existing API keys
- Create new keys with optional scopes and expiration
- Revoke keys
- Copy raw key on creation (only shown once)

### RBAC Demo (`/rbac`)
- Assign roles (admin, user, viewer)
- Add/remove individual permissions
- Check if you have a specific permission

### Admin (`/admin`)
Admin-only page with:
- User list
- Revoke all tokens for a user
- Cleanup statistics
- Manual cleanup trigger

## Configuration

Environment variables (or defaults in `config.go`):

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 8080 | Server port |
| DATABASE_DSN | postgres://goauth:goauth@localhost:15432/goauth_test | PostgreSQL connection |
| JWT_SECRET | your-secret-key-change-in-production | JWT signing key |
| ACCESS_TOKEN_TTL | 15m | Access token lifetime |
| REFRESH_TOKEN_TTL | 168h (7 days) | Refresh token lifetime |

## RBAC Configuration

See `permissions.yaml` for role and permission definitions:

```yaml
permission_groups:
  - name: Users
    permissions:
      - users:read
      - users:write
      - users:delete

roles:
  - key: admin
    name: Administrator
    permissions:
      - "*"  # Full access

  - key: user
    name: User
    permissions:
      - users:read
      - apikeys:*
```
