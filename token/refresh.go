package token

import (
	"context"
	"time"

	"github.com/aloks98/goauth/internal/crypto"
	"github.com/aloks98/goauth/internal/hash"
	"github.com/aloks98/goauth/store"
)

// RefreshTokenResult contains the generated refresh token and its metadata.
type RefreshTokenResult struct {
	Token     string    // Raw token to give to client (only shown once)
	JTI       string    // Token ID for tracking
	FamilyID  string    // Family ID for rotation tracking
	ExpiresAt time.Time // When the token expires
}

// GenerateRefreshToken creates a new refresh token for a user.
func (s *Service) GenerateRefreshToken(ctx context.Context, userID string) (*RefreshTokenResult, error) {
	result, err := s.generateRefreshTokenWithFamily(ctx, userID, "")
	if err != nil {
		return nil, err
	}
	// Format the token for client use
	result.Token = formatRefreshToken(result.JTI, result.Token)
	return result, nil
}

// generateRefreshTokenWithFamily creates a refresh token with a specific family ID.
// If familyID is empty, a new family is created.
func (s *Service) generateRefreshTokenWithFamily(ctx context.Context, userID, familyID string) (*RefreshTokenResult, error) {
	// Generate secure random token
	rawToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}

	// Generate JTI
	jti, err := crypto.GenerateID()
	if err != nil {
		return nil, err
	}

	// Generate or use existing family ID
	if familyID == "" {
		familyID, err = crypto.GenerateID()
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()
	expiresAt := now.Add(s.config.RefreshTokenTTL)

	// Hash the token for storage
	tokenHash := hash.SHA256(rawToken)

	// Create the refresh token record
	refreshToken := &store.RefreshToken{
		ID:        jti,
		UserID:    userID,
		FamilyID:  familyID,
		TokenHash: tokenHash,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}

	// Store the token
	if err := s.store.SaveRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	return &RefreshTokenResult{
		Token:     rawToken,
		JTI:       jti,
		FamilyID:  familyID,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateRefreshToken validates a refresh token and returns its metadata.
func (s *Service) ValidateRefreshToken(ctx context.Context, rawToken string) (*store.RefreshToken, error) {
	// Parse the token to extract JTI and random part
	jti, randomPart, err := parseRefreshToken(rawToken)
	if err != nil {
		return nil, ErrRefreshTokenInvalid
	}

	// Look up the token by JTI
	storedToken, err := s.store.GetRefreshToken(ctx, jti)
	if err != nil {
		return nil, err
	}
	if storedToken == nil {
		return nil, ErrRefreshTokenInvalid
	}

	// Verify the hash matches (we hash the random part only)
	expectedHash := hash.SHA256(randomPart)
	if !hash.ConstantTimeCompare(storedToken.TokenHash, expectedHash) {
		return nil, ErrRefreshTokenInvalid
	}

	// Check if token is revoked
	if storedToken.IsRevoked() {
		return nil, ErrRefreshTokenReused
	}

	// Check if token is expired
	if storedToken.IsExpired() {
		return nil, ErrRefreshTokenExpired
	}

	return storedToken, nil
}

// RotateRefreshToken validates the old token, revokes it, and issues a new pair.
func (s *Service) RotateRefreshToken(ctx context.Context, rawToken string) (*Pair, error) {
	// Parse the token to extract JTI and random part
	jti, randomPart, err := parseRefreshToken(rawToken)
	if err != nil {
		return nil, ErrRefreshTokenInvalid
	}

	// Look up the token
	storedToken, err := s.store.GetRefreshToken(ctx, jti)
	if err != nil {
		return nil, err
	}
	if storedToken == nil {
		return nil, ErrRefreshTokenInvalid
	}

	// Verify the hash matches (we hash only the random part)
	expectedHash := hash.SHA256(randomPart)
	if !hash.ConstantTimeCompare(storedToken.TokenHash, expectedHash) {
		return nil, ErrRefreshTokenInvalid
	}

	// Check if token is already revoked (theft detection!)
	if storedToken.IsRevoked() {
		// Token reuse detected! Revoke the entire family
		if err := s.store.RevokeTokenFamily(ctx, storedToken.FamilyID); err != nil {
			return nil, err
		}
		return nil, ErrRefreshTokenReused
	}

	// Check if token is expired
	if storedToken.IsExpired() {
		return nil, ErrRefreshTokenExpired
	}

	// Generate new refresh token in the same family
	newRefreshToken, err := s.generateRefreshTokenWithFamily(ctx, storedToken.UserID, storedToken.FamilyID)
	if err != nil {
		return nil, err
	}

	// Revoke the old token, marking what replaced it
	if err := s.store.RevokeRefreshToken(ctx, jti, newRefreshToken.JTI); err != nil {
		return nil, err
	}

	// Get permission version
	var permissionVersion int
	if s.config.PermissionVersionCheck {
		perms, err := s.store.GetUserPermissions(ctx, storedToken.UserID)
		if err != nil {
			return nil, err
		}
		if perms != nil {
			permissionVersion = perms.PermissionVersion
		}
	}

	// Generate new access token
	accessToken, _, expiresAt, err := s.generateAccessToken(storedToken.UserID, permissionVersion, nil)
	if err != nil {
		return nil, err
	}

	return &Pair{
		AccessToken:  accessToken,
		RefreshToken: formatRefreshToken(newRefreshToken.JTI, newRefreshToken.Token),
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenTTL.Seconds()),
		ExpiresAt:    expiresAt,
	}, nil
}

// formatRefreshToken creates the client-facing refresh token format.
// Format: base64url(jti).base64url(random)
func formatRefreshToken(jti, random string) string {
	return jti + "." + random
}

// parseRefreshToken extracts JTI and random part from the token.
func parseRefreshToken(token string) (jti, random string, err error) {
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			return token[:i], token[i+1:], nil
		}
	}
	return "", "", ErrRefreshTokenInvalid
}
