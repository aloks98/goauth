# Token Service

## Overview

The token service handles JWT access tokens and refresh tokens with rotation and theft detection.

## Token Types

### Access Token

| Property | Value |
|----------|-------|
| Format | JWT (RS256 or HS256) |
| Default TTL | 15 minutes |
| Storage | Not stored (stateless validation) |
| Revocation | Via blacklist |
| Contains | User ID, permissions version, custom claims |

### Refresh Token

| Property | Value |
|----------|-------|
| Format | Signed JWT or opaque token |
| Default TTL | 7 days |
| Storage | Stored in database |
| Revocation | Mark as revoked in DB |
| Contains | User ID, family ID, JTI |

## Token Pair Structure

```go
type TokenPair struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`     // "Bearer"
    ExpiresIn    int64     `json:"expires_in"`     // Seconds
    ExpiresAt    time.Time `json:"expires_at"`
}
```

## Claims Structure

### Standard Claims (Always Included)

```go
type StandardClaims struct {
    // JWT standard claims
    Subject   string `json:"sub"`  // User ID
    JTI       string `json:"jti"`  // Unique token ID
    IssuedAt  int64  `json:"iat"`
    ExpiresAt int64  `json:"exp"`
    
    // GoAuth specific
    PermissionVersion int `json:"pv"`  // For detecting permission changes
}
```

### Custom Claims (Application Defined)

```go
// Application defines their claims struct
type MyClaims struct {
    goauth.StandardClaims          // Embed standard claims
    TenantID  string `json:"tenant_id"`
    Role      string `json:"role"`
    TeamID    string `json:"team_id,omitempty"`
}
```

## Token Lifecycle

### Generation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Token Generation Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. App calls auth.GenerateTokenPair(userID)                    │
│                    │                                             │
│                    ▼                                             │
│  2. Fetch user permissions from store                            │
│     • Get current permissions list                               │
│     • Get current permission version                             │
│                    │                                             │
│                    ▼                                             │
│  3. Generate access token                                        │
│     • Create JWT with user ID, permission version               │
│     • Sign with secret key                                       │
│     • Set expiry (15 min)                                       │
│                    │                                             │
│                    ▼                                             │
│  4. Generate refresh token                                       │
│     • Generate unique JTI and family ID                         │
│     • Create signed token or opaque string                      │
│     • Store metadata in database:                                │
│       - JTI, user ID, family ID                                 │
│       - Token hash, issued at, expires at                       │
│                    │                                             │
│                    ▼                                             │
│  5. Return TokenPair                                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Validation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Token Validation Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Extract token from Authorization header                      │
│     Authorization: Bearer <token>                                │
│                    │                                             │
│                    ▼                                             │
│  2. Parse and validate JWT                                       │
│     • Check signature                                            │
│     • Check expiry                                               │
│     • Check issued at (not in future)                           │
│        │                                                         │
│        ├─► Invalid signature → ErrTokenInvalidSig               │
│        ├─► Expired → ErrTokenExpired                            │
│        └─► Malformed → ErrTokenMalformed                        │
│                    │                                             │
│                    ▼                                             │
│  3. Check blacklist                                              │
│     • Look up JTI in blacklist store                            │
│        │                                                         │
│        └─► Found → ErrTokenBlacklisted                          │
│                    │                                             │
│                    ▼                                             │
│  4. Check permission version (optional)                          │
│     • Fetch current version from store                          │
│     • Compare with token's version                               │
│        │                                                         │
│        └─► Mismatch → ErrPermissionsChanged                     │
│                    │                                             │
│                    ▼                                             │
│  5. Return validated claims                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Refresh Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Token Refresh Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Client sends refresh token                                   │
│     POST /auth/refresh { "refresh_token": "..." }               │
│                    │                                             │
│                    ▼                                             │
│  2. Validate refresh token signature/format                      │
│        │                                                         │
│        └─► Invalid → ErrRefreshTokenInvalid                     │
│                    │                                             │
│                    ▼                                             │
│  3. Look up refresh token in database                            │
│        │                                                         │
│        ├─► Not found → ErrRefreshTokenInvalid                   │
│        ├─► Expired → ErrRefreshTokenExpired                     │
│        └─► Already revoked → Check for theft (step 4)           │
│                    │                                             │
│                    ▼                                             │
│  4. Theft detection (if token was already used)                  │
│     • Token reuse indicates theft                                │
│     • Revoke entire token family                                 │
│        │                                                         │
│        └─► Reuse detected → ErrRefreshTokenReused               │
│                    │                                             │
│                    ▼                                             │
│  5. Rotate refresh token                                         │
│     • Mark old token as revoked                                  │
│     • Set "replaced_by" to new token's JTI                      │
│     • Generate new refresh token (same family ID)               │
│                    │                                             │
│                    ▼                                             │
│  6. Generate new access token                                    │
│     • Fetch fresh user permissions                               │
│     • Create new JWT with current permission version            │
│                    │                                             │
│                    ▼                                             │
│  7. Return new TokenPair                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Refresh Token Family

Tokens are grouped into "families" to detect theft.

```
Family: abc123
├── Token A (initial login)
│   └── Revoked, replaced_by: Token B
├── Token B (first refresh)
│   └── Revoked, replaced_by: Token C
└── Token C (second refresh)
    └── Active
```

**Theft Detection:**

If Token B is used again after Token C was issued:
1. Token B is already marked as revoked
2. This indicates the token was stolen (legitimate user has Token C)
3. Revoke entire family (including Token C)
4. User must re-authenticate

## Blacklist Strategy

Access tokens are blacklisted for instant revocation.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Blacklist Entry                               │
├─────────────────────────────────────────────────────────────────┤
│  JTI: "abc123-def456"                                           │
│  Expires: 2024-01-15 10:30:00 (matches token expiry)           │
│                                                                  │
│  Storage: Redis or SQL table with TTL                           │
│  Cleanup: Automatic (TTL) or background worker                  │
└─────────────────────────────────────────────────────────────────┘
```

## Interface Definition

```go
type TokenService interface {
    // Generation
    GenerateTokenPair(userID string, customClaims any) (*TokenPair, error)
    GenerateAccessToken(claims Claims) (string, error)
    GenerateRefreshToken(userID string) (*RefreshToken, error)
    
    // Validation
    ValidateAccessToken(token string) (*Claims, error)
    ValidateRefreshToken(token string) (*RefreshTokenMeta, error)
    
    // Refresh
    RefreshTokens(refreshToken string) (*TokenPair, error)
    
    // Revocation
    RevokeAccessToken(jti string) error
    RevokeRefreshToken(jti string) error
    RevokeTokenFamily(familyID string) error
    RevokeAllUserTokens(userID string) error
    
    // Blacklist check
    IsBlacklisted(jti string) (bool, error)
}
```

## Configuration Options

```go
goauth.WithAccessTokenTTL(15 * time.Minute)      // Default: 15 minutes
goauth.WithRefreshTokenTTL(7 * 24 * time.Hour)   // Default: 7 days
goauth.WithSigningMethod(goauth.HS256)            // Default: HS256
goauth.WithSigningMethod(goauth.RS256)            // Alternative: RS256
goauth.WithPrivateKey(privateKey)                 // For RS256
goauth.WithPublicKey(publicKey)                   // For RS256
```
