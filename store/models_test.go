package store

import (
	"testing"
	"time"
)

func TestRefreshToken_IsRevoked(t *testing.T) {
	tests := []struct {
		name      string
		revokedAt *time.Time
		expected  bool
	}{
		{
			name:      "not revoked",
			revokedAt: nil,
			expected:  false,
		},
		{
			name:      "revoked",
			revokedAt: func() *time.Time { t := time.Now(); return &t }(),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &RefreshToken{RevokedAt: tt.revokedAt}
			if got := token.IsRevoked(); got != tt.expected {
				t.Errorf("IsRevoked() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRefreshToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(time.Hour),
			expected:  false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &RefreshToken{ExpiresAt: tt.expiresAt}
			if got := token.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRefreshToken_IsValid(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		token     *RefreshToken
		expected  bool
	}{
		{
			name: "valid token",
			token: &RefreshToken{
				ExpiresAt: now.Add(time.Hour),
				RevokedAt: nil,
			},
			expected: true,
		},
		{
			name: "expired token",
			token: &RefreshToken{
				ExpiresAt: now.Add(-time.Hour),
				RevokedAt: nil,
			},
			expected: false,
		},
		{
			name: "revoked token",
			token: &RefreshToken{
				ExpiresAt: now.Add(time.Hour),
				RevokedAt: &now,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUserPermissions_HasPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		required    string
		expected    bool
	}{
		{
			name:        "exact match",
			permissions: []string{"monitors:read", "monitors:write"},
			required:    "monitors:read",
			expected:    true,
		},
		{
			name:        "no match",
			permissions: []string{"monitors:read"},
			required:    "monitors:write",
			expected:    false,
		},
		{
			name:        "wildcard action",
			permissions: []string{"monitors:*"},
			required:    "monitors:read",
			expected:    true,
		},
		{
			name:        "wildcard resource",
			permissions: []string{"*:read"},
			required:    "monitors:read",
			expected:    true,
		},
		{
			name:        "superuser wildcard",
			permissions: []string{"*"},
			required:    "anything:here",
			expected:    true,
		},
		{
			name:        "wildcard doesn't match different action",
			permissions: []string{"*:read"},
			required:    "monitors:write",
			expected:    false,
		},
		{
			name:        "wildcard doesn't match different resource",
			permissions: []string{"monitors:*"},
			required:    "alerts:read",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &UserPermissions{Permissions: tt.permissions}
			if got := up.HasPermission(tt.required); got != tt.expected {
				t.Errorf("HasPermission(%q) = %v, want %v", tt.required, got, tt.expected)
			}
		})
	}
}

func TestUserPermissions_HasAllPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		required    []string
		expected    bool
	}{
		{
			name:        "has all",
			permissions: []string{"monitors:read", "monitors:write", "alerts:read"},
			required:    []string{"monitors:read", "alerts:read"},
			expected:    true,
		},
		{
			name:        "missing one",
			permissions: []string{"monitors:read"},
			required:    []string{"monitors:read", "monitors:write"},
			expected:    false,
		},
		{
			name:        "empty required",
			permissions: []string{"monitors:read"},
			required:    []string{},
			expected:    true,
		},
		{
			name:        "superuser has all",
			permissions: []string{"*"},
			required:    []string{"monitors:read", "alerts:write"},
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &UserPermissions{Permissions: tt.permissions}
			if got := up.HasAllPermissions(tt.required); got != tt.expected {
				t.Errorf("HasAllPermissions() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUserPermissions_HasAnyPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		required    []string
		expected    bool
	}{
		{
			name:        "has one",
			permissions: []string{"monitors:read"},
			required:    []string{"monitors:read", "monitors:write"},
			expected:    true,
		},
		{
			name:        "has none",
			permissions: []string{"alerts:read"},
			required:    []string{"monitors:read", "monitors:write"},
			expected:    false,
		},
		{
			name:        "empty required",
			permissions: []string{"monitors:read"},
			required:    []string{},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &UserPermissions{Permissions: tt.permissions}
			if got := up.HasAnyPermission(tt.required); got != tt.expected {
				t.Errorf("HasAnyPermission() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIKey_IsRevoked(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		revokedAt *time.Time
		expected  bool
	}{
		{"not revoked", nil, false},
		{"revoked", &now, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{RevokedAt: tt.revokedAt}
			if got := key.IsRevoked(); got != tt.expected {
				t.Errorf("IsRevoked() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIKey_IsExpired(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	tests := []struct {
		name      string
		expiresAt *time.Time
		expected  bool
	}{
		{"never expires", nil, false},
		{"not expired", &future, false},
		{"expired", &past, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{ExpiresAt: tt.expiresAt}
			if got := key.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIKey_IsValid(t *testing.T) {
	now := time.Now()
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	tests := []struct {
		name     string
		key      *APIKey
		expected bool
	}{
		{
			name:     "valid with no expiry",
			key:      &APIKey{},
			expected: true,
		},
		{
			name:     "valid with future expiry",
			key:      &APIKey{ExpiresAt: &future},
			expected: true,
		},
		{
			name:     "expired",
			key:      &APIKey{ExpiresAt: &past},
			expected: false,
		},
		{
			name:     "revoked",
			key:      &APIKey{RevokedAt: &now},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIKey_HasScope(t *testing.T) {
	tests := []struct {
		name       string
		scopes     []string
		permission string
		expected   bool
	}{
		{
			name:       "no scopes means all permissions",
			scopes:     nil,
			permission: "anything:here",
			expected:   true,
		},
		{
			name:       "empty scopes means all permissions",
			scopes:     []string{},
			permission: "anything:here",
			expected:   true,
		},
		{
			name:       "exact scope match",
			scopes:     []string{"monitors:read"},
			permission: "monitors:read",
			expected:   true,
		},
		{
			name:       "wildcard scope",
			scopes:     []string{"monitors:*"},
			permission: "monitors:read",
			expected:   true,
		},
		{
			name:       "scope not matched",
			scopes:     []string{"monitors:read"},
			permission: "monitors:write",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Scopes: tt.scopes}
			if got := key.HasScope(tt.permission); got != tt.expected {
				t.Errorf("HasScope(%q) = %v, want %v", tt.permission, got, tt.expected)
			}
		})
	}
}

func TestMatchPermission(t *testing.T) {
	tests := []struct {
		have     string
		want     string
		expected bool
	}{
		{"monitors:read", "monitors:read", true},
		{"monitors:read", "monitors:write", false},
		{"monitors:*", "monitors:read", true},
		{"monitors:*", "monitors:write", true},
		{"*:read", "monitors:read", true},
		{"*:read", "alerts:read", true},
		{"*:read", "monitors:write", false},
		{"*", "anything:here", true},
		{"*", "single", true},
	}

	for _, tt := range tests {
		t.Run(tt.have+"->"+tt.want, func(t *testing.T) {
			if got := matchPermission(tt.have, tt.want); got != tt.expected {
				t.Errorf("matchPermission(%q, %q) = %v, want %v", tt.have, tt.want, got, tt.expected)
			}
		})
	}
}

func TestSplitPermission(t *testing.T) {
	tests := []struct {
		perm           string
		wantResource   string
		wantAction     string
	}{
		{"monitors:read", "monitors", "read"},
		{"monitors:write", "monitors", "write"},
		{"*:read", "*", "read"},
		{"monitors:*", "monitors", "*"},
		{"single", "single", ""},
		{"a:b:c", "a", "b:c"},
	}

	for _, tt := range tests {
		t.Run(tt.perm, func(t *testing.T) {
			resource, action := splitPermission(tt.perm)
			if resource != tt.wantResource {
				t.Errorf("resource = %q, want %q", resource, tt.wantResource)
			}
			if action != tt.wantAction {
				t.Errorf("action = %q, want %q", action, tt.wantAction)
			}
		})
	}
}
