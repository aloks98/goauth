package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aloks98/goauth/internal/crypto"
)

// Claims represents the JWT claims structure.
type Claims struct {
	UserID            string         `json:"sub"`
	JTI               string         `json:"jti"`
	PermissionVersion int            `json:"pv,omitempty"`
	Custom            map[string]any `json:"custom,omitempty"`
	jwt.RegisteredClaims
}

// GetUserID returns the user ID from claims.
func (c *Claims) GetUserID() string {
	return c.UserID
}

// GetJTI returns the JWT ID.
func (c *Claims) GetJTI() string {
	return c.JTI
}

// generateAccessToken creates a new JWT access token.
func (s *Service) generateAccessToken(userID string, permissionVersion int, customClaims map[string]any) (string, string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.AccessTokenTTL)

	// Generate unique JTI
	jti, err := crypto.GenerateID()
	if err != nil {
		return "", "", time.Time{}, err
	}

	claims := &Claims{
		UserID:            userID,
		JTI:               jti,
		PermissionVersion: permissionVersion,
		Custom:            customClaims,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(s.jwtSigningMethod, claims)

	var signedToken string
	switch s.jwtSigningMethod.(type) {
	case *jwt.SigningMethodHMAC:
		signedToken, err = token.SignedString([]byte(s.config.Secret))
	case *jwt.SigningMethodRSA:
		signedToken, err = token.SignedString(s.config.PrivateKey)
	default:
		signedToken, err = token.SignedString([]byte(s.config.Secret))
	}

	if err != nil {
		return "", "", time.Time{}, err
	}

	return signedToken, jti, expiresAt, nil
}

// parseAndValidateJWT parses and validates a JWT token.
func (s *Service) parseAndValidateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		// Validate signing method
		switch s.jwtSigningMethod.(type) {
		case *jwt.SigningMethodHMAC:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrTokenInvalidSig
			}
			return []byte(s.config.Secret), nil
		case *jwt.SigningMethodRSA:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, ErrTokenInvalidSig
			}
			return s.config.PublicKey, nil
		default:
			return []byte(s.config.Secret), nil
		}
	}, jwt.WithLeeway(s.config.ClockSkew))

	if err != nil {
		return nil, mapJWTError(err)
	}

	if !token.Valid {
		return nil, ErrTokenMalformed
	}

	return claims, nil
}

// mapJWTError maps JWT library errors to our error types.
func mapJWTError(err error) error {
	if err == nil {
		return nil
	}

	// JWT v5 uses specific error types
	if errors.Is(err, jwt.ErrTokenExpired) {
		return ErrTokenExpired
	}
	if errors.Is(err, jwt.ErrTokenNotValidYet) {
		return ErrTokenNotYetValid
	}
	if errors.Is(err, jwt.ErrTokenMalformed) {
		return ErrTokenMalformed
	}
	if errors.Is(err, jwt.ErrSignatureInvalid) {
		return ErrTokenInvalidSig
	}
	if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return ErrTokenInvalidSig
	}
	if errors.Is(err, jwt.ErrTokenUnverifiable) {
		return ErrTokenInvalidSig
	}

	return ErrTokenMalformed
}
