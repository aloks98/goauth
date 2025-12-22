package goauth

import (
	"errors"
	"fmt"
)

// Error codes for categorizing errors.
const (
	CodeTokenExpired           = "TOKEN_EXPIRED"
	CodeTokenNotYetValid       = "TOKEN_NOT_YET_VALID"
	CodeTokenMalformed         = "TOKEN_MALFORMED"
	CodeTokenInvalidSignature  = "TOKEN_INVALID_SIGNATURE"
	CodeTokenBlacklisted       = "TOKEN_BLACKLISTED"
	CodePermissionsChanged     = "PERMISSIONS_CHANGED"
	CodeRefreshTokenReused     = "REFRESH_TOKEN_REUSED"
	CodeRefreshTokenExpired    = "REFRESH_TOKEN_EXPIRED"
	CodeRefreshTokenInvalid    = "REFRESH_TOKEN_INVALID"
	CodeTokenFamilyRevoked     = "TOKEN_FAMILY_REVOKED"
	CodeAPIKeyInvalid          = "API_KEY_INVALID"
	CodeAPIKeyExpired          = "API_KEY_EXPIRED"
	CodeAPIKeyRevoked          = "API_KEY_REVOKED"
	CodePasswordTooWeak        = "PASSWORD_TOO_WEAK"
	CodePasswordMismatch       = "PASSWORD_MISMATCH"
	CodeRateLimitExceeded      = "RATE_LIMIT_EXCEEDED"
	CodeStoreRequired          = "STORE_REQUIRED"
	CodeStoreUnavailable       = "STORE_UNAVAILABLE"
	CodeStoreTimeout           = "STORE_TIMEOUT"
	CodeConfigInvalid          = "CONFIG_INVALID"
	CodeConfigVersionInvalid   = "CONFIG_VERSION_UNSUPPORTED"
	CodeDuplicatePermission    = "DUPLICATE_PERMISSION"
	CodeDuplicateRole          = "DUPLICATE_ROLE"
	CodeRolePermissionNotFound = "ROLE_PERMISSION_NOT_FOUND"
	CodeEmptyPermissionKey     = "EMPTY_PERMISSION_KEY"
	CodeInvalidPermissionFmt   = "INVALID_PERMISSION_FORMAT"
	CodePermissionDenied       = "PERMISSION_DENIED"
	CodeUserPermsNotFound      = "USER_PERMISSIONS_NOT_FOUND"
	CodeRBACNotEnabled         = "RBAC_NOT_ENABLED"
)

// Sentinel errors for use with errors.Is().
var (
	// Token errors
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenNotYetValid   = errors.New("token is not yet valid")
	ErrTokenMalformed     = errors.New("token is malformed")
	ErrTokenInvalidSig    = errors.New("token signature is invalid")
	ErrTokenBlacklisted   = errors.New("token has been revoked")
	ErrPermissionsChanged = errors.New("user permissions have changed, please refresh token")

	// Refresh token errors
	ErrRefreshTokenReused  = errors.New("refresh token has already been used (possible token theft)")
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid")
	ErrTokenFamilyRevoked  = errors.New("token family has been revoked")

	// API key errors
	ErrAPIKeyInvalid = errors.New("API key is invalid")
	ErrAPIKeyExpired = errors.New("API key has expired")
	ErrAPIKeyRevoked = errors.New("API key has been revoked")

	// Password errors
	ErrPasswordTooWeak  = errors.New("password does not meet strength requirements")
	ErrPasswordMismatch = errors.New("password does not match")

	// Rate limit errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// Store errors
	ErrStoreRequired    = errors.New("store is required")
	ErrStoreUnavailable = errors.New("store is unavailable")
	ErrStoreTimeout     = errors.New("store operation timed out")

	// Config errors
	ErrConfigInvalid            = errors.New("configuration is invalid")
	ErrConfigVersionUnsupported = errors.New("configuration version is not supported")
	ErrDuplicatePermission      = errors.New("duplicate permission key")
	ErrDuplicateRole            = errors.New("duplicate role key")
	ErrRolePermissionNotFound   = errors.New("role references undefined permission")
	ErrEmptyPermissionKey       = errors.New("permission key cannot be empty")
	ErrInvalidPermissionFormat  = errors.New("invalid permission format")

	// Permission errors
	ErrPermissionDenied        = errors.New("permission denied")
	ErrUserPermissionsNotFound = errors.New("user permissions not found")

	// RBAC mode errors
	ErrRBACNotEnabled = errors.New("RBAC is not enabled")
)

// AuthError is a structured error type that includes an error code and optional wrapped error.
type AuthError struct {
	Code    string
	Message string
	Err     error
}

// Error implements the error interface.
func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for use with errors.Is() and errors.As().
func (e *AuthError) Unwrap() error {
	return e.Err
}

// NewAuthError creates a new AuthError with the given code, message, and optional wrapped error.
func NewAuthError(code, message string, err error) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// WrapError wraps a sentinel error with additional context.
func WrapError(code string, err error, message string) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// IsTokenError returns true if the error is a token-related error.
func IsTokenError(err error) bool {
	return errors.Is(err, ErrTokenExpired) ||
		errors.Is(err, ErrTokenNotYetValid) ||
		errors.Is(err, ErrTokenMalformed) ||
		errors.Is(err, ErrTokenInvalidSig) ||
		errors.Is(err, ErrTokenBlacklisted) ||
		errors.Is(err, ErrPermissionsChanged)
}

// IsRefreshTokenError returns true if the error is a refresh token-related error.
func IsRefreshTokenError(err error) bool {
	return errors.Is(err, ErrRefreshTokenReused) ||
		errors.Is(err, ErrRefreshTokenExpired) ||
		errors.Is(err, ErrRefreshTokenInvalid) ||
		errors.Is(err, ErrTokenFamilyRevoked)
}

// IsAPIKeyError returns true if the error is an API key-related error.
func IsAPIKeyError(err error) bool {
	return errors.Is(err, ErrAPIKeyInvalid) ||
		errors.Is(err, ErrAPIKeyExpired) ||
		errors.Is(err, ErrAPIKeyRevoked)
}

// IsConfigError returns true if the error is a configuration-related error.
func IsConfigError(err error) bool {
	return errors.Is(err, ErrConfigInvalid) ||
		errors.Is(err, ErrConfigVersionUnsupported) ||
		errors.Is(err, ErrDuplicatePermission) ||
		errors.Is(err, ErrDuplicateRole) ||
		errors.Is(err, ErrRolePermissionNotFound) ||
		errors.Is(err, ErrEmptyPermissionKey) ||
		errors.Is(err, ErrInvalidPermissionFormat)
}
