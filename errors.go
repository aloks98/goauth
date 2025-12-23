package goauth

import (
	"errors"
	"fmt"

	"github.com/aloks98/goauth/apikey"
	"github.com/aloks98/goauth/rbac"
	"github.com/aloks98/goauth/token"
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

// Re-exported errors from sub-packages.
// These allow users to use goauth.ErrXxx without importing sub-packages.
var (
	// Token errors (from token package)
	ErrTokenExpired       = token.ErrTokenExpired
	ErrTokenNotYetValid   = token.ErrTokenNotYetValid
	ErrTokenMalformed     = token.ErrTokenMalformed
	ErrTokenInvalidSig    = token.ErrTokenInvalidSig
	ErrTokenBlacklisted   = token.ErrTokenBlacklisted
	ErrPermissionsChanged = token.ErrPermissionsChanged

	// Refresh token errors (from token package)
	ErrRefreshTokenReused  = token.ErrRefreshTokenReused
	ErrRefreshTokenExpired = token.ErrRefreshTokenExpired
	ErrRefreshTokenInvalid = token.ErrRefreshTokenInvalid
	ErrTokenFamilyRevoked  = token.ErrTokenFamilyRevoked

	// API key errors (from apikey package)
	ErrAPIKeyInvalid = apikey.ErrKeyInvalid
	ErrAPIKeyExpired = apikey.ErrKeyExpired
	ErrAPIKeyRevoked = apikey.ErrKeyRevoked

	// RBAC errors (from rbac package)
	ErrRBACNotEnabled          = rbac.ErrRBACNotEnabled
	ErrPermissionDenied        = rbac.ErrPermissionDenied
	ErrUserPermissionsNotFound = rbac.ErrUserPermissionsNotFound
	ErrDuplicatePermission     = rbac.ErrDuplicatePermission
	ErrDuplicateRole           = rbac.ErrDuplicateRole
	ErrRolePermissionNotFound  = rbac.ErrRolePermissionNotFound
	ErrEmptyPermissionKey      = rbac.ErrEmptyPermissionKey
	ErrInvalidPermissionFormat = rbac.ErrInvalidPermissionFormat

	// Rate limit errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// Store errors
	ErrStoreRequired    = errors.New("store is required")
	ErrStoreUnavailable = errors.New("store is unavailable")
	ErrStoreTimeout     = errors.New("store operation timed out")

	// Config errors
	ErrConfigInvalid            = errors.New("configuration is invalid")
	ErrConfigVersionUnsupported = errors.New("configuration version is not supported")
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
