package goauth

import (
	"errors"
	"testing"
)

func TestAuthError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AuthError
		expected string
	}{
		{
			name: "with wrapped error",
			err: &AuthError{
				Code:    CodeTokenExpired,
				Message: "token has expired",
				Err:     ErrTokenExpired,
			},
			expected: "TOKEN_EXPIRED: token has expired: token has expired",
		},
		{
			name: "without wrapped error",
			err: &AuthError{
				Code:    CodePermissionDenied,
				Message: "access denied",
			},
			expected: "PERMISSION_DENIED: access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("AuthError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestAuthError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	authErr := &AuthError{
		Code:    CodeTokenExpired,
		Message: "token error",
		Err:     underlying,
	}

	if authErr.Unwrap() != underlying {
		t.Error("Unwrap() should return the underlying error")
	}

	// Test errors.Is works
	if !errors.Is(authErr, underlying) {
		t.Error("errors.Is should find underlying error")
	}
}

func TestNewAuthError(t *testing.T) {
	err := NewAuthError(CodeTokenExpired, "test message", ErrTokenExpired)

	if err.Code != CodeTokenExpired {
		t.Errorf("Code = %q, want %q", err.Code, CodeTokenExpired)
	}
	if err.Message != "test message" {
		t.Errorf("Message = %q, want %q", err.Message, "test message")
	}
	if err.Err != ErrTokenExpired {
		t.Error("Err should be ErrTokenExpired")
	}
}

func TestWrapError(t *testing.T) {
	err := WrapError(CodePermissionDenied, ErrPermissionDenied, "access denied to resource")

	if !errors.Is(err, ErrPermissionDenied) {
		t.Error("wrapped error should be detectable with errors.Is")
	}
}

func TestIsTokenError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{ErrTokenExpired, true},
		{ErrTokenNotYetValid, true},
		{ErrTokenMalformed, true},
		{ErrTokenInvalidSig, true},
		{ErrTokenBlacklisted, true},
		{ErrPermissionsChanged, true},
		{ErrRefreshTokenReused, false},
		{ErrAPIKeyInvalid, false},
		{errors.New("random error"), false},
	}

	for _, tt := range tests {
		if got := IsTokenError(tt.err); got != tt.expected {
			t.Errorf("IsTokenError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}

func TestIsRefreshTokenError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{ErrRefreshTokenReused, true},
		{ErrRefreshTokenExpired, true},
		{ErrRefreshTokenInvalid, true},
		{ErrTokenFamilyRevoked, true},
		{ErrTokenExpired, false},
		{ErrAPIKeyInvalid, false},
	}

	for _, tt := range tests {
		if got := IsRefreshTokenError(tt.err); got != tt.expected {
			t.Errorf("IsRefreshTokenError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}

func TestIsAPIKeyError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{ErrAPIKeyInvalid, true},
		{ErrAPIKeyExpired, true},
		{ErrAPIKeyRevoked, true},
		{ErrTokenExpired, false},
	}

	for _, tt := range tests {
		if got := IsAPIKeyError(tt.err); got != tt.expected {
			t.Errorf("IsAPIKeyError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}

func TestIsConfigError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{ErrConfigInvalid, true},
		{ErrConfigVersionUnsupported, true},
		{ErrDuplicatePermission, true},
		{ErrDuplicateRole, true},
		{ErrRolePermissionNotFound, true},
		{ErrEmptyPermissionKey, true},
		{ErrInvalidPermissionFormat, true},
		{ErrTokenExpired, false},
	}

	for _, tt := range tests {
		if got := IsConfigError(tt.err); got != tt.expected {
			t.Errorf("IsConfigError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}
