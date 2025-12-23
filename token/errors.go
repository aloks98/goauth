package token

import "errors"

// Token-related errors.
var (
	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("token has expired")

	// ErrTokenNotYetValid indicates the token is not yet valid (iat in future).
	ErrTokenNotYetValid = errors.New("token is not yet valid")

	// ErrTokenMalformed indicates the token format is invalid.
	ErrTokenMalformed = errors.New("token is malformed")

	// ErrTokenInvalidSig indicates the token signature is invalid.
	ErrTokenInvalidSig = errors.New("token signature is invalid")

	// ErrTokenBlacklisted indicates the token has been revoked.
	ErrTokenBlacklisted = errors.New("token has been revoked")

	// ErrPermissionsChanged indicates user permissions have changed.
	ErrPermissionsChanged = errors.New("user permissions have changed")

	// ErrRefreshTokenInvalid indicates the refresh token is invalid.
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid")

	// ErrRefreshTokenExpired indicates the refresh token has expired.
	ErrRefreshTokenExpired = errors.New("refresh token has expired")

	// ErrRefreshTokenReused indicates token reuse was detected (possible theft).
	ErrRefreshTokenReused = errors.New("refresh token reuse detected")

	// ErrTokenFamilyRevoked indicates the token family has been revoked.
	ErrTokenFamilyRevoked = errors.New("token family has been revoked")
)
