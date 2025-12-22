# Phase 2: Token Service

**Duration:** 4-5 days
**Goal:** Implement JWT access tokens and refresh tokens with rotation.

**Dependencies:** Phase 1 (Foundation)

---

## Tasks

### 2.1 JWT Generation

**Description:** Implement JWT token generation in `token/jwt.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [ ] Generate JWT with HS256 signing (default)
- [ ] Support HS384, HS512 signing methods
- [ ] Support RS256, RS384, RS512 signing methods
- [ ] Include standard claims (sub, jti, iat, exp)
- [ ] Include custom claims from generic type
- [ ] Include permission version in claims
- [ ] Generate unique JTI using UUID

**Implementation:**
```go
func (s *Service) generateJWT(claims any, ttl time.Duration) (string, error)
```

**Testing:**
- [ ] Unit test: Generated token is valid JWT format
- [ ] Unit test: Token contains all standard claims
- [ ] Unit test: Token contains custom claims
- [ ] Unit test: Token expiry matches TTL
- [ ] Unit test: Different signing methods work
- [ ] Unit test: RS256 with key pair works

---

### 2.2 JWT Validation

**Description:** Implement JWT token validation in `token/jwt.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [ ] Validate JWT signature
- [ ] Check token expiration
- [ ] Check token not-before (iat)
- [ ] Extract and return claims
- [ ] Return specific errors for different failures
- [ ] Support clock skew tolerance

**Implementation:**
```go
func (s *Service) validateJWT(tokenString string) (*Claims, error)
```

**Testing:**
- [ ] Unit test: Valid token returns claims
- [ ] Unit test: Expired token returns `ErrTokenExpired`
- [ ] Unit test: Invalid signature returns `ErrTokenInvalidSig`
- [ ] Unit test: Malformed token returns `ErrTokenMalformed`
- [ ] Unit test: Future token returns `ErrTokenNotYetValid`
- [ ] Unit test: Clock skew tolerance works

---

### 2.3 Refresh Token Generation

**Description:** Implement refresh token generation in `token/refresh.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [ ] Generate secure random refresh token
- [ ] Create family ID for new login sessions
- [ ] Store token hash in database (not raw token)
- [ ] Set expiration time
- [ ] Return token and metadata

**Implementation:**
```go
type RefreshToken struct {
    Token     string    // Raw token to give to client
    JTI       string
    FamilyID  string
    ExpiresAt time.Time
}

func (s *Service) GenerateRefreshToken(ctx context.Context, userID string) (*RefreshToken, error)
```

**Testing:**
- [ ] Unit test: Token is sufficiently random (entropy check)
- [ ] Unit test: Token is stored in database
- [ ] Unit test: Token hash is stored, not raw token
- [ ] Unit test: Family ID is generated for new sessions
- [ ] Unit test: Expiration is set correctly

---

### 2.4 Refresh Token Validation

**Description:** Implement refresh token validation in `token/refresh.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [ ] Look up token by hash in database
- [ ] Check token exists
- [ ] Check token not expired
- [ ] Check token not revoked
- [ ] Return token metadata on success

**Implementation:**
```go
func (s *Service) ValidateRefreshToken(ctx context.Context, token string) (*RefreshTokenMeta, error)
```

**Testing:**
- [ ] Unit test: Valid token returns metadata
- [ ] Unit test: Unknown token returns `ErrRefreshTokenInvalid`
- [ ] Unit test: Expired token returns `ErrRefreshTokenExpired`
- [ ] Unit test: Revoked token triggers theft detection

---

### 2.5 Token Rotation

**Description:** Implement refresh token rotation in `token/refresh.go`.

**Estimated Hours:** 5

**Acceptance Criteria:**
- [ ] Validate old refresh token
- [ ] Mark old token as revoked
- [ ] Set `replaced_by` to new token's JTI
- [ ] Generate new refresh token (same family)
- [ ] Generate new access token with fresh permissions
- [ ] Detect token reuse (theft detection)
- [ ] Revoke entire family on reuse detection

**Implementation:**
```go
func (s *Service) RotateRefreshToken(ctx context.Context, oldToken string) (*TokenPair, error)
```

**Theft Detection Flow:**
```
1. Token A is issued (family: xyz)
2. Token A is used, Token B issued (A marked revoked, replaced_by: B)
3. Token A is used again (already revoked!)
4. Entire family xyz is revoked
5. Return ErrRefreshTokenReused
```

**Testing:**
- [ ] Unit test: Rotation returns new token pair
- [ ] Unit test: Old token is marked revoked
- [ ] Unit test: New token has same family ID
- [ ] Unit test: Reuse of old token revokes family
- [ ] Unit test: Reuse returns `ErrRefreshTokenReused`
- [ ] Integration test: Full rotation flow

---

### 2.6 Token Blacklist

**Description:** Implement access token blacklist in `token/blacklist.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [ ] Add JTI to blacklist with expiry
- [ ] Check if JTI is blacklisted
- [ ] Blacklist entry expires when token would expire
- [ ] Efficient lookup (indexed)

**Implementation:**
```go
func (s *Service) AddToBlacklist(ctx context.Context, jti string, expiresAt time.Time) error
func (s *Service) IsBlacklisted(ctx context.Context, jti string) (bool, error)
```

**Testing:**
- [ ] Unit test: Blacklisted token is detected
- [ ] Unit test: Non-blacklisted token passes
- [ ] Unit test: Expired blacklist entries are ignored

---

### 2.7 Token Pair Generation

**Description:** Implement combined token pair generation in `token/service.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [ ] Fetch user permissions from store
- [ ] Generate access token with permission version
- [ ] Generate refresh token
- [ ] Store refresh token
- [ ] Return `TokenPair` struct

**Implementation:**
```go
type TokenPair struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`
    ExpiresIn    int64     `json:"expires_in"`
    ExpiresAt    time.Time `json:"expires_at"`
}

func (s *Service) GenerateTokenPair(ctx context.Context, userID string, customClaims any) (*TokenPair, error)
```

**Testing:**
- [ ] Unit test: Returns both tokens
- [ ] Unit test: Access token contains permission version
- [ ] Unit test: Refresh token is stored
- [ ] Integration test: Full flow with store

---

### 2.8 Token Revocation

**Description:** Implement token revocation methods in `token/service.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [ ] Revoke single access token (blacklist)
- [ ] Revoke single refresh token
- [ ] Revoke entire token family
- [ ] Revoke all tokens for a user

**Implementation:**
```go
func (s *Service) RevokeAccessToken(ctx context.Context, jti string) error
func (s *Service) RevokeRefreshToken(ctx context.Context, jti string) error
func (s *Service) RevokeTokenFamily(ctx context.Context, familyID string) error
func (s *Service) RevokeAllUserTokens(ctx context.Context, userID string) error
```

**Testing:**
- [ ] Unit test: Revoked access token is blacklisted
- [ ] Unit test: Revoked refresh token marked in DB
- [ ] Unit test: Family revocation marks all tokens
- [ ] Unit test: User revocation handles all tokens

---

### 2.9 Permission Version Check

**Description:** Implement permission version checking during validation.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [ ] Fetch current permission version from store
- [ ] Compare with token's permission version
- [ ] Return `ErrPermissionsChanged` on mismatch
- [ ] Cache permission version for performance

**Testing:**
- [ ] Unit test: Matching version passes
- [ ] Unit test: Mismatched version returns error
- [ ] Unit test: Cache is used when enabled
- [ ] Unit test: Cache invalidation works

---

## Phase 2 Checklist

- [ ] JWT generation implemented and tested
- [ ] JWT validation implemented and tested
- [ ] Refresh token generation implemented and tested
- [ ] Refresh token validation implemented and tested
- [ ] Token rotation with theft detection implemented and tested
- [ ] Token blacklist implemented and tested
- [ ] Token pair generation implemented and tested
- [ ] Token revocation implemented and tested
- [ ] Permission version check implemented and tested
- [ ] All unit tests pass
- [ ] Integration tests with memory store pass

## Integration Test Scenarios

```go
func TestTokenService_FullFlow(t *testing.T) {
    // 1. Generate token pair
    // 2. Validate access token
    // 3. Refresh tokens
    // 4. Validate new access token
    // 5. Revoke tokens
    // 6. Validate fails
}

func TestTokenService_TheftDetection(t *testing.T) {
    // 1. Generate token pair
    // 2. Refresh (get new pair)
    // 3. Use old refresh token again
    // 4. Verify entire family is revoked
}

func TestTokenService_PermissionVersionChange(t *testing.T) {
    // 1. Generate token pair
    // 2. Change user permissions (bump version)
    // 3. Validate access token
    // 4. Verify ErrPermissionsChanged
}
```

## Test Commands

```bash
# Run token package tests
go test ./token/... -v

# Run with coverage
go test ./token/... -cover

# Run integration tests
go test ./token/... -tags=integration
```
