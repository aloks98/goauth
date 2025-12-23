// Package token provides JWT access token and refresh token management.
package token

import (
	"context"
	"crypto/rsa"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aloks98/goauth/store"
)

// Pair represents an access/refresh token pair returned to clients.
type Pair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Config holds configuration for the token service.
type Config struct {
	// Secret is the HMAC signing key (for HS* methods).
	Secret string

	// PrivateKey is the RSA private key (for RS* methods).
	PrivateKey *rsa.PrivateKey

	// PublicKey is the RSA public key (for RS* methods).
	PublicKey *rsa.PublicKey

	// SigningMethod is the JWT signing algorithm.
	SigningMethod string

	// AccessTokenTTL is the access token lifetime.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the refresh token lifetime.
	RefreshTokenTTL time.Duration

	// ClockSkew allows for clock differences between servers.
	ClockSkew time.Duration

	// PermissionVersionCheck enables permission version validation.
	PermissionVersionCheck bool
}

// Service handles token generation, validation, and management.
type Service struct {
	config *Config
	store  store.Store

	// jwtSigningMethod is the resolved JWT signing method.
	jwtSigningMethod jwt.SigningMethod

	// permissionCache caches user permission versions.
	permissionCache sync.Map
}

// NewService creates a new token service.
func NewService(cfg *Config, s store.Store) *Service {
	svc := &Service{
		config: cfg,
		store:  s,
	}

	// Resolve signing method
	switch cfg.SigningMethod {
	case "HS256":
		svc.jwtSigningMethod = jwt.SigningMethodHS256
	case "HS384":
		svc.jwtSigningMethod = jwt.SigningMethodHS384
	case "HS512":
		svc.jwtSigningMethod = jwt.SigningMethodHS512
	case "RS256":
		svc.jwtSigningMethod = jwt.SigningMethodRS256
	case "RS384":
		svc.jwtSigningMethod = jwt.SigningMethodRS384
	case "RS512":
		svc.jwtSigningMethod = jwt.SigningMethodRS512
	default:
		svc.jwtSigningMethod = jwt.SigningMethodHS256
	}

	return svc
}

// GenerateTokenPair generates a new access/refresh token pair.
func (s *Service) GenerateTokenPair(ctx context.Context, userID string, customClaims map[string]any) (*Pair, error) {
	// Get permission version if RBAC is enabled
	var permissionVersion int
	if s.config.PermissionVersionCheck {
		perms, err := s.store.GetUserPermissions(ctx, userID)
		if err != nil {
			return nil, err
		}
		if perms != nil {
			permissionVersion = perms.PermissionVersion
		}
	}

	// Generate access token
	accessToken, jti, expiresAt, err := s.generateAccessToken(userID, permissionVersion, customClaims)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := s.GenerateRefreshToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	_ = jti // JTI available for logging if needed

	return &Pair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenTTL.Seconds()),
		ExpiresAt:    expiresAt,
	}, nil
}

// ValidateAccessToken validates an access token and returns the claims.
func (s *Service) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := s.parseAndValidateJWT(tokenString)
	if err != nil {
		return nil, err
	}

	// Check blacklist
	blacklisted, err := s.store.IsBlacklisted(ctx, claims.JTI)
	if err != nil {
		return nil, err
	}
	if blacklisted {
		return nil, ErrTokenBlacklisted
	}

	// Check permission version if enabled
	if s.config.PermissionVersionCheck {
		currentVersion, err := s.getCurrentPermissionVersion(ctx, claims.UserID)
		if err != nil {
			return nil, err
		}
		if claims.PermissionVersion != currentVersion {
			return nil, ErrPermissionsChanged
		}
	}

	return claims, nil
}

// RefreshTokens validates a refresh token and returns a new token pair.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken string) (*Pair, error) {
	return s.RotateRefreshToken(ctx, refreshToken)
}

// RevokeAccessToken adds an access token to the blacklist.
func (s *Service) RevokeAccessToken(ctx context.Context, tokenString string) error {
	claims, err := s.parseAndValidateJWT(tokenString)
	if err != nil {
		// Even if token is expired/invalid, try to blacklist if we can extract JTI
		// This handles edge cases where we want to revoke a token that's about to expire
		return err
	}

	return s.AddToBlacklist(ctx, claims.JTI, claims.ExpiresAt.Time)
}

// RevokeRefreshToken revokes a specific refresh token.
func (s *Service) RevokeRefreshToken(ctx context.Context, jti string) error {
	return s.store.RevokeRefreshToken(ctx, jti, "")
}

// RevokeTokenFamily revokes all tokens in a family.
func (s *Service) RevokeTokenFamily(ctx context.Context, familyID string) error {
	return s.store.RevokeTokenFamily(ctx, familyID)
}

// RevokeAllUserTokens revokes all tokens for a user.
func (s *Service) RevokeAllUserTokens(ctx context.Context, userID string) error {
	return s.store.RevokeAllUserRefreshTokens(ctx, userID)
}

// getCurrentPermissionVersion gets the current permission version for a user.
func (s *Service) getCurrentPermissionVersion(ctx context.Context, userID string) (int, error) {
	perms, err := s.store.GetUserPermissions(ctx, userID)
	if err != nil {
		return 0, err
	}
	if perms == nil {
		return 0, nil
	}
	return perms.PermissionVersion, nil
}

// InvalidatePermissionCache clears the cached permission version for a user.
func (s *Service) InvalidatePermissionCache(userID string) {
	s.permissionCache.Delete(userID)
}
