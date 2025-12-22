# OAuth2/OIDC Integration

## Overview

GoAuth works seamlessly with OAuth2/OIDC providers using external libraries. GoAuth doesn't include OAuth adapters - instead, you use well-maintained OAuth libraries for identity verification, then GoAuth handles your application's tokens and permissions.

**Recommended Libraries:**
- `golang.org/x/oauth2` - OAuth2 flows
- `google.golang.org/api/idtoken` - Google ID token verification
- `github.com/coreos/go-oidc/v3` - Generic OIDC verification

## How It Works

```
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                            │
│  1. User clicks "Login with Google"                                        │
│                      │                                                     │
│                      ▼                                                     │
│  2. Your app redirects to Google (using golang.org/x/oauth2)              │
│                      │                                                     │
│                      ▼                                                     │
│  3. User authenticates with Google                                         │
│                      │                                                     │
│                      ▼                                                     │
│  4. Google redirects back with authorization code                          │
│                      │                                                     │
│                      ▼                                                     │
│  5. Your app exchanges code for tokens (using golang.org/x/oauth2)        │
│                      │                                                     │
│                      ▼                                                     │
│  6. Your app verifies ID token (using google.golang.org/api/idtoken)      │
│                      │                                                     │
│                      ▼                                                     │
│  7. Your app finds/creates user in YOUR database                           │
│                      │                                                     │
│                      ▼                                                     │
│  8. GoAuth generates YOUR tokens ◄─── GoAuth enters here                  │
│                      │                                                     │
│                      ▼                                                     │
│  9. Client receives YOUR tokens (not Google's)                             │
│                      │                                                     │
│                      ▼                                                     │
│  10. All API calls use YOUR tokens, validated by GoAuth                    │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

**Key Point:** Google/GitHub tokens are used **once** to verify identity. GoAuth tokens are used for **all subsequent API calls**.

---

## Complete Example: Google + GitHub Login

### Project Structure

```
myapp/
├── main.go
├── handlers/
│   ├── auth.go          # Login, logout, refresh
│   ├── google.go        # Google OAuth
│   └── github.go        # GitHub OAuth
├── middleware/
│   └── auth.go          # GoAuth middleware setup
├── models/
│   └── user.go          # User and OAuthAccount models
├── config/
│   └── permissions.yaml # GoAuth RBAC config
├── .env
└── go.mod
```

### Dependencies

```bash
go get github.com/yourusername/goauth
go get golang.org/x/oauth2
go get google.golang.org/api/idtoken
```

### Environment Variables

```bash
# .env
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

GOAUTH_SECRET=your-very-secure-256-bit-secret-key
DATABASE_URL=postgres://user:pass@localhost/myapp

BASE_URL=http://localhost:8080
```

### Database Schema

```sql
-- Your users table (you manage this)
CREATE TABLE users (
    id          VARCHAR(36) PRIMARY KEY,
    email       VARCHAR(255) UNIQUE NOT NULL,
    name        VARCHAR(255),
    avatar_url  VARCHAR(500),
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW()
);

-- OAuth account links (you manage this)
CREATE TABLE oauth_accounts (
    id          VARCHAR(36) PRIMARY KEY,
    user_id     VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider    VARCHAR(50) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    email       VARCHAR(255),
    created_at  TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(provider, provider_id)
);

-- GoAuth manages its own tables (auto-migrated):
-- auth_user_permissions
-- auth_refresh_tokens
-- auth_token_blacklist
-- auth_role_templates
-- auth_api_keys
```

### Main Application

```go
// main.go
package main

import (
    "log"
    "net/http"
    "os"
    "time"

    "github.com/yourusername/goauth"
    "github.com/yourusername/goauth/store/sql"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/github"
    "golang.org/x/oauth2/google"
)

// Custom claims for your application
type Claims struct {
    goauth.StandardClaims
    Email string `json:"email,omitempty"`
}

// OAuth configs (global for simplicity)
var (
    googleOAuthConfig *oauth2.Config
    githubOAuthConfig *oauth2.Config
    auth              *goauth.Auth[Claims]
)

func main() {
    // Initialize OAuth configs
    googleOAuthConfig = &oauth2.Config{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  os.Getenv("BASE_URL") + "/auth/google/callback",
        Scopes:       []string{"openid", "email", "profile"},
        Endpoint:     google.Endpoint,
    }

    githubOAuthConfig = &oauth2.Config{
        ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
        ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        RedirectURL:  os.Getenv("BASE_URL") + "/auth/github/callback",
        Scopes:       []string{"user:email"},
        Endpoint:     github.Endpoint,
    }

    // Initialize GoAuth
    var err error
    auth, err = goauth.New[Claims](
        goauth.WithSecret(os.Getenv("GOAUTH_SECRET")),
        goauth.WithStore(sql.Postgres(os.Getenv("DATABASE_URL"))),
        goauth.WithRBACFromFile("./config/permissions.yaml"),
        goauth.WithAutoMigrate(true),
        goauth.WithAccessTokenTTL(15*time.Minute),
        goauth.WithRefreshTokenTTL(7*24*time.Hour),
    )
    if err != nil {
        log.Fatalf("Failed to initialize GoAuth: %v", err)
    }
    defer auth.Close()

    // Setup routes
    mux := http.NewServeMux()

    // Public routes
    mux.HandleFunc("GET /", handleHome)
    mux.HandleFunc("GET /auth/google/login", handleGoogleLogin)
    mux.HandleFunc("GET /auth/google/callback", handleGoogleCallback)
    mux.HandleFunc("GET /auth/github/login", handleGitHubLogin)
    mux.HandleFunc("GET /auth/github/callback", handleGitHubCallback)
    mux.HandleFunc("POST /auth/refresh", handleRefreshToken)
    mux.HandleFunc("POST /auth/logout", handleLogout)

    // Protected routes
    mw := auth.Middleware()
    mux.Handle("GET /api/me", mw.Authenticate(http.HandlerFunc(handleMe)))
    mux.Handle("GET /api/monitors", mw.Authenticate(
        mw.RequirePermission("monitors:read")(http.HandlerFunc(handleListMonitors)),
    ))

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### Google OAuth Handlers

```go
// handlers/google.go
package main

import (
    "context"
    "encoding/json"
    "net/http"
    "time"

    "google.golang.org/api/idtoken"
)

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
    // Generate state for CSRF protection
    state := generateSecureToken(32)
    
    // Store state in cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        Path:     "/",
        HttpOnly: true,
        Secure:   true, // Set to false for localhost
        SameSite: http.SameSiteLaxMode,
        MaxAge:   int(5 * time.Minute / time.Second),
    })

    // Redirect to Google
    url := googleOAuthConfig.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // ===========================================
    // Step 1: Validate state (CSRF protection)
    // ===========================================
    stateCookie, err := r.Cookie("oauth_state")
    if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
        http.Error(w, "Invalid state parameter", http.StatusBadRequest)
        return
    }

    // Clear the state cookie
    http.SetCookie(w, &http.Cookie{
        Name:   "oauth_state",
        Path:   "/",
        MaxAge: -1,
    })

    // Check for errors from Google
    if errMsg := r.URL.Query().Get("error"); errMsg != "" {
        http.Error(w, "OAuth error: "+errMsg, http.StatusBadRequest)
        return
    }

    // ===========================================
    // Step 2: Exchange code for tokens
    // ===========================================
    code := r.URL.Query().Get("code")
    token, err := googleOAuthConfig.Exchange(ctx, code)
    if err != nil {
        http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusBadRequest)
        return
    }

    // ===========================================
    // Step 3: Verify ID token
    // ===========================================
    idToken, ok := token.Extra("id_token").(string)
    if !ok {
        http.Error(w, "No ID token in response", http.StatusBadRequest)
        return
    }

    payload, err := idtoken.Validate(ctx, idToken, googleOAuthConfig.ClientID)
    if err != nil {
        http.Error(w, "Invalid ID token: "+err.Error(), http.StatusUnauthorized)
        return
    }

    // ===========================================
    // Step 4: Extract user info
    // ===========================================
    providerUser := OAuthUser{
        Provider:      "google",
        ProviderID:    payload.Subject,
        Email:         getStringClaim(payload.Claims, "email"),
        EmailVerified: getBoolClaim(payload.Claims, "email_verified"),
        Name:          getStringClaim(payload.Claims, "name"),
        Picture:       getStringClaim(payload.Claims, "picture"),
    }

    // ===========================================
    // Step 5: Find or create user + generate tokens
    // ===========================================
    tokens, err := processOAuthLogin(ctx, providerUser)
    if err != nil {
        http.Error(w, "Login failed: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // ===========================================
    // Step 6: Return tokens to client
    // ===========================================
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(tokens)
}

// Helper functions
func getStringClaim(claims map[string]interface{}, key string) string {
    if val, ok := claims[key].(string); ok {
        return val
    }
    return ""
}

func getBoolClaim(claims map[string]interface{}, key string) bool {
    if val, ok := claims[key].(bool); ok {
        return val
    }
    return false
}
```

### GitHub OAuth Handlers

```go
// handlers/github.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
    state := generateSecureToken(32)

    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   int(5 * time.Minute / time.Second),
    })

    url := githubOAuthConfig.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Validate state
    stateCookie, err := r.Cookie("oauth_state")
    if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
        http.Error(w, "Invalid state parameter", http.StatusBadRequest)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:   "oauth_state",
        Path:   "/",
        MaxAge: -1,
    })

    // Exchange code for token
    code := r.URL.Query().Get("code")
    token, err := githubOAuthConfig.Exchange(ctx, code)
    if err != nil {
        http.Error(w, "Failed to exchange code", http.StatusBadRequest)
        return
    }

    // ===========================================
    // GitHub doesn't have ID tokens - call their API
    // ===========================================
    githubUser, err := fetchGitHubUser(ctx, token.AccessToken)
    if err != nil {
        http.Error(w, "Failed to fetch user info", http.StatusBadRequest)
        return
    }

    // GitHub may not return email in user response - fetch separately
    email := githubUser.Email
    if email == "" {
        email, _ = fetchGitHubPrimaryEmail(ctx, token.AccessToken)
    }

    providerUser := OAuthUser{
        Provider:      "github",
        ProviderID:    fmt.Sprintf("%d", githubUser.ID),
        Email:         email,
        EmailVerified: true, // GitHub verifies emails
        Name:          githubUser.Name,
        Picture:       githubUser.AvatarURL,
    }

    // Find or create user + generate tokens
    tokens, err := processOAuthLogin(ctx, providerUser)
    if err != nil {
        http.Error(w, "Login failed: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(tokens)
}

// GitHub API types
type GitHubUser struct {
    ID        int    `json:"id"`
    Login     string `json:"login"`
    Name      string `json:"name"`
    Email     string `json:"email"`
    AvatarURL string `json:"avatar_url"`
}

type GitHubEmail struct {
    Email    string `json:"email"`
    Primary  bool   `json:"primary"`
    Verified bool   `json:"verified"`
}

func fetchGitHubUser(ctx context.Context, accessToken string) (*GitHubUser, error) {
    req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Accept", "application/vnd.github.v3+json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var user GitHubUser
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        return nil, err
    }
    return &user, nil
}

func fetchGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
    req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Accept", "application/vnd.github.v3+json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var emails []GitHubEmail
    if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
        return "", err
    }

    for _, email := range emails {
        if email.Primary && email.Verified {
            return email.Email, nil
        }
    }
    return "", nil
}
```

### Common OAuth Processing

```go
// handlers/auth.go
package main

import (
    "context"
    "crypto/rand"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "net/http"

    "github.com/google/uuid"
    "github.com/yourusername/goauth"
)

// OAuthUser represents normalized user info from any provider
type OAuthUser struct {
    Provider      string
    ProviderID    string
    Email         string
    EmailVerified bool
    Name          string
    Picture       string
}

// processOAuthLogin handles the common logic after OAuth verification
func processOAuthLogin(ctx context.Context, ou OAuthUser) (*goauth.TokenPair, error) {
    // ===========================================
    // Step 1: Find or create user
    // ===========================================
    user, isNew, err := findOrCreateUser(ctx, ou)
    if err != nil {
        return nil, err
    }

    // ===========================================
    // Step 2: Initialize permissions for new users
    // ===========================================
    if isNew {
        if err := auth.AssignRole(ctx, user.ID, "viewer"); err != nil {
            return nil, err
        }
    }

    // ===========================================
    // Step 3: Generate GoAuth tokens
    // ===========================================
    tokens, err := auth.GenerateTokenPair(ctx, user.ID, Claims{
        Email: user.Email,
    })
    if err != nil {
        return nil, err
    }

    return tokens, nil
}

// User model
type User struct {
    ID        string
    Email     string
    Name      string
    AvatarURL string
}

func findOrCreateUser(ctx context.Context, ou OAuthUser) (*User, bool, error) {
    // Try to find existing user by OAuth link
    user, err := findUserByOAuth(ctx, ou.Provider, ou.ProviderID)
    if err == nil {
        return user, false, nil
    }

    // Try to find user by email (link new provider to existing account)
    if ou.Email != "" && ou.EmailVerified {
        user, err = findUserByEmail(ctx, ou.Email)
        if err == nil {
            // Link this provider to existing user
            if err := createOAuthLink(ctx, user.ID, ou); err != nil {
                return nil, false, err
            }
            return user, false, nil
        }
    }

    // Create new user
    user = &User{
        ID:        uuid.New().String(),
        Email:     ou.Email,
        Name:      ou.Name,
        AvatarURL: ou.Picture,
    }

    if err := createUser(ctx, user); err != nil {
        return nil, false, err
    }

    if err := createOAuthLink(ctx, user.ID, ou); err != nil {
        return nil, false, err
    }

    return user, true, nil
}

// Database functions (implement with your DB layer)
func findUserByOAuth(ctx context.Context, provider, providerID string) (*User, error) {
    // SELECT u.* FROM users u
    // JOIN oauth_accounts oa ON oa.user_id = u.id
    // WHERE oa.provider = $1 AND oa.provider_id = $2
    return nil, sql.ErrNoRows // placeholder
}

func findUserByEmail(ctx context.Context, email string) (*User, error) {
    // SELECT * FROM users WHERE email = $1
    return nil, sql.ErrNoRows // placeholder
}

func createUser(ctx context.Context, user *User) error {
    // INSERT INTO users (id, email, name, avatar_url) VALUES (...)
    return nil // placeholder
}

func createOAuthLink(ctx context.Context, userID string, ou OAuthUser) error {
    // INSERT INTO oauth_accounts (id, user_id, provider, provider_id, email) VALUES (...)
    return nil // placeholder
}

// Token refresh handler
func handleRefreshToken(w http.ResponseWriter, r *http.Request) {
    var req struct {
        RefreshToken string `json:"refresh_token"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    tokens, err := auth.RefreshTokens(r.Context(), req.RefreshToken)
    if err != nil {
        http.Error(w, "Refresh failed: "+err.Error(), http.StatusUnauthorized)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(tokens)
}

// Logout handler
func handleLogout(w http.ResponseWriter, r *http.Request) {
    var req struct {
        RefreshToken string `json:"refresh_token"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    // Get user from token
    claims := goauth.ClaimsFromContext[Claims](r.Context())
    if claims != nil {
        auth.RevokeAllUserTokens(r.Context(), claims.UserID)
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
}

// Get current user handler
func handleMe(w http.ResponseWriter, r *http.Request) {
    claims := goauth.ClaimsFromContext[Claims](r.Context())

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]any{
        "user_id": claims.UserID,
        "email":   claims.Email,
    })
}

// Utility functions
func generateSecureToken(length int) string {
    b := make([]byte, length)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    w.Write([]byte(`
        <h1>GoAuth OAuth Example</h1>
        <p><a href="/auth/google/login">Login with Google</a></p>
        <p><a href="/auth/github/login">Login with GitHub</a></p>
    `))
}

func handleListMonitors(w http.ResponseWriter, r *http.Request) {
    claims := goauth.ClaimsFromContext[Claims](r.Context())
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]any{
        "user_id":  claims.UserID,
        "monitors": []string{"monitor-1", "monitor-2"},
    })
}
```

### Permissions Config

```yaml
# config/permissions.yaml
version: 1

permission_groups:
  - key: monitors
    name: Monitors
    description: Monitor management
    permissions:
      - key: monitors:read
        name: View monitors
      - key: monitors:write
        name: Create and edit monitors
      - key: monitors:delete
        name: Delete monitors

  - key: alerts
    name: Alerts
    description: Alert management
    permissions:
      - key: alerts:read
        name: View alerts
      - key: alerts:write
        name: Manage alerts

role_templates:
  - key: viewer
    name: Viewer
    description: Read-only access
    permissions:
      - monitors:read
      - alerts:read

  - key: editor
    name: Editor
    description: Can create and modify
    permissions:
      - monitors:read
      - monitors:write
      - alerts:read
      - alerts:write

  - key: admin
    name: Admin
    description: Full access
    permissions:
      - monitors:*
      - alerts:*
```

---

## Mobile / SPA Flow

For mobile apps and SPAs where the client handles OAuth directly:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Mobile App  │     │  Your API    │     │   Google     │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  1. Google Sign-In SDK                  │
       │─────────────────────────────────────────▶
       │                    │                    │
       │  2. ID Token       │                    │
       │◀─────────────────────────────────────────
       │                    │                    │
       │  3. POST /auth/google/token             │
       │       { "id_token": "..." }             │
       │───────────────────▶│                    │
       │                    │                    │
       │                    │ 4. Verify token    │
       │                    │ 5. Find/create user│
       │                    │ 6. GoAuth tokens   │
       │                    │                    │
       │  7. Your tokens    │                    │
       │◀───────────────────│                    │
       │                    │                    │
       │  8. API calls with your tokens          │
       │───────────────────▶│                    │
```

```go
// Handler for mobile/SPA clients that send ID token directly
func handleGoogleTokenLogin(w http.ResponseWriter, r *http.Request) {
    var req struct {
        IDToken string `json:"id_token"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Verify the ID token
    payload, err := idtoken.Validate(r.Context(), req.IDToken, googleOAuthConfig.ClientID)
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    providerUser := OAuthUser{
        Provider:      "google",
        ProviderID:    payload.Subject,
        Email:         getStringClaim(payload.Claims, "email"),
        EmailVerified: getBoolClaim(payload.Claims, "email_verified"),
        Name:          getStringClaim(payload.Claims, "name"),
        Picture:       getStringClaim(payload.Claims, "picture"),
    }

    tokens, err := processOAuthLogin(r.Context(), providerUser)
    if err != nil {
        http.Error(w, "Login failed", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(tokens)
}
```

---

## Adding More Providers

### Generic OIDC Provider (Okta, Auth0, etc.)

```go
import "github.com/coreos/go-oidc/v3/oidc"

var oidcProvider *oidc.Provider
var oidcVerifier *oidc.IDTokenVerifier

func initOIDCProvider() {
    ctx := context.Background()
    
    // Works with any OIDC provider
    provider, _ := oidc.NewProvider(ctx, "https://your-domain.okta.com")
    
    oidcVerifier = provider.Verifier(&oidc.Config{
        ClientID: os.Getenv("OIDC_CLIENT_ID"),
    })
}

func handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
    // ... exchange code for tokens ...
    
    // Verify ID token using go-oidc
    idToken, err := oidcVerifier.Verify(r.Context(), rawIDToken)
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }
    
    var claims struct {
        Sub           string `json:"sub"`
        Email         string `json:"email"`
        EmailVerified bool   `json:"email_verified"`
        Name          string `json:"name"`
        Picture       string `json:"picture"`
    }
    idToken.Claims(&claims)
    
    providerUser := OAuthUser{
        Provider:      "okta",
        ProviderID:    claims.Sub,
        Email:         claims.Email,
        EmailVerified: claims.EmailVerified,
        Name:          claims.Name,
        Picture:       claims.Picture,
    }
    
    tokens, _ := processOAuthLogin(r.Context(), providerUser)
    json.NewEncoder(w).Encode(tokens)
}
```

### Microsoft / Azure AD

```go
import (
    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2/microsoft"
)

var microsoftOAuthConfig = &oauth2.Config{
    ClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
    ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
    RedirectURL:  os.Getenv("BASE_URL") + "/auth/microsoft/callback",
    Scopes:       []string{"openid", "email", "profile"},
    Endpoint:     microsoft.AzureADEndpoint(os.Getenv("MICROSOFT_TENANT_ID")),
    // Use "common" for multi-tenant, or specific tenant ID
}

func initMicrosoftOIDC() {
    ctx := context.Background()
    tenantID := os.Getenv("MICROSOFT_TENANT_ID")
    
    issuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
    provider, _ := oidc.NewProvider(ctx, issuer)
    
    microsoftVerifier = provider.Verifier(&oidc.Config{
        ClientID: os.Getenv("MICROSOFT_CLIENT_ID"),
    })
}
```

### Apple Sign In

```go
import "github.com/Timothylock/go-signin-with-apple/apple"

func handleAppleCallback(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")
    
    // Apple requires generating a client secret JWT
    secret, _ := apple.GenerateClientSecret(
        os.Getenv("APPLE_SECRET_KEY"),   // P-256 private key
        os.Getenv("APPLE_TEAM_ID"),
        os.Getenv("APPLE_CLIENT_ID"),
        os.Getenv("APPLE_KEY_ID"),
    )
    
    // Exchange code
    client := apple.New()
    token, _ := client.VerifyAppToken(r.Context(), apple.AppValidationTokenRequest{
        ClientID:     os.Getenv("APPLE_CLIENT_ID"),
        ClientSecret: secret,
        Code:         code,
    })
    
    // Parse ID token claims
    claims, _ := apple.GetClaims(token.IDToken)
    
    providerUser := OAuthUser{
        Provider:      "apple",
        ProviderID:    claims.Subject,
        Email:         claims.Email,
        EmailVerified: claims.EmailVerified,
        // Apple may hide real email behind relay address
    }
    
    tokens, _ := processOAuthLogin(r.Context(), providerUser)
    json.NewEncoder(w).Encode(tokens)
}
```

---

## Security Checklist

- [x] **State parameter**: Always generate and validate to prevent CSRF
- [x] **HTTPS**: Use HTTPS for all redirect URLs in production
- [x] **Token storage**: Store GoAuth tokens securely (httpOnly cookies or secure storage)
- [x] **Email verification**: Check `email_verified` claim before trusting email
- [x] **Audience validation**: Verify `aud` claim matches your client ID
- [x] **Expiry validation**: ID tokens are automatically checked for expiry

---

## Summary

| Component | Library | Purpose |
|-----------|---------|---------|
| OAuth2 flow | `golang.org/x/oauth2` | Redirect, code exchange |
| Google ID token | `google.golang.org/api/idtoken` | Verify Google tokens |
| Generic OIDC | `github.com/coreos/go-oidc/v3` | Verify any OIDC provider |
| GitHub user info | HTTP client | Fetch user from GitHub API |
| Your tokens | **GoAuth** | Generate, validate, refresh |
| Your permissions | **GoAuth** | RBAC, roles, middleware |

GoAuth focuses on **your application's authentication** - JWT tokens, refresh rotation, permissions, and middleware. OAuth libraries handle **identity verification** from external providers.
