// Package memory provides an in-memory store implementation for testing.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/aloks98/goauth/store"
)

// Store is an in-memory implementation of the store.Store interface.
// It is intended for testing and development purposes.
type Store struct {
	mu sync.RWMutex

	refreshTokens   map[string]*store.RefreshToken
	blacklist       map[string]*store.BlacklistEntry
	userPermissions map[string]*store.UserPermissions
	roleTemplates   map[string]*store.StoredRoleTemplate
	apiKeys         map[string]*store.APIKey

	closed bool
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		refreshTokens:   make(map[string]*store.RefreshToken),
		blacklist:       make(map[string]*store.BlacklistEntry),
		userPermissions: make(map[string]*store.UserPermissions),
		roleTemplates:   make(map[string]*store.StoredRoleTemplate),
		apiKeys:         make(map[string]*store.APIKey),
	}
}

// Close marks the store as closed.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// Ping checks if the store is available.
func (s *Store) Ping(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return nil
}

// Migrate is a no-op for the memory store.
func (s *Store) Migrate(ctx context.Context) error {
	return nil
}

// SaveRefreshToken saves a refresh token.
func (s *Store) SaveRefreshToken(ctx context.Context, token *store.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token.ID] = token
	return nil
}

// GetRefreshToken retrieves a refresh token by JTI.
func (s *Store) GetRefreshToken(ctx context.Context, jti string) (*store.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refreshTokens[jti], nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (s *Store) RevokeRefreshToken(ctx context.Context, jti string, replacedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token, ok := s.refreshTokens[jti]; ok {
		now := time.Now()
		token.RevokedAt = &now
		token.ReplacedBy = &replacedBy
	}
	return nil
}

// RevokeTokenFamily revokes all tokens in a family.
func (s *Store) RevokeTokenFamily(ctx context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, token := range s.refreshTokens {
		if token.FamilyID == familyID {
			token.RevokedAt = &now
		}
	}
	return nil
}

// RevokeAllUserRefreshTokens revokes all tokens for a user.
func (s *Store) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, token := range s.refreshTokens {
		if token.UserID == userID {
			token.RevokedAt = &now
		}
	}
	return nil
}

// DeleteExpiredRefreshTokens removes expired tokens.
func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	now := time.Now()
	for id, token := range s.refreshTokens {
		if token.ExpiresAt.Before(now) {
			delete(s.refreshTokens, id)
			count++
		}
	}
	return count, nil
}

// AddToBlacklist adds a JTI to the blacklist.
func (s *Store) AddToBlacklist(ctx context.Context, jti string, expiresAt int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blacklist[jti] = &store.BlacklistEntry{
		JTI:       jti,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	return nil
}

// IsBlacklisted checks if a JTI is blacklisted.
func (s *Store) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.blacklist[jti]
	return ok, nil
}

// DeleteExpiredBlacklistEntries removes expired blacklist entries.
func (s *Store) DeleteExpiredBlacklistEntries(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	now := time.Now().Unix()
	for jti, entry := range s.blacklist {
		if entry.ExpiresAt < now {
			delete(s.blacklist, jti)
			count++
		}
	}
	return count, nil
}

// GetUserPermissions retrieves user permissions.
func (s *Store) GetUserPermissions(ctx context.Context, userID string) (*store.UserPermissions, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.userPermissions[userID], nil
}

// SaveUserPermissions saves user permissions.
func (s *Store) SaveUserPermissions(ctx context.Context, perms *store.UserPermissions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userPermissions[perms.UserID] = perms
	return nil
}

// DeleteUserPermissions removes user permissions.
func (s *Store) DeleteUserPermissions(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.userPermissions, userID)
	return nil
}

// UpdateUsersWithRole updates all users with a specific role.
func (s *Store) UpdateUsersWithRole(ctx context.Context, roleLabel string, permissions []string, newVersion int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for _, perms := range s.userPermissions {
		if perms.RoleLabel == roleLabel {
			perms.Permissions = permissions
			perms.PermissionVersion = newVersion
			perms.UpdatedAt = time.Now()
			count++
		}
	}
	return count, nil
}

// GetRoleTemplates retrieves all role templates.
func (s *Store) GetRoleTemplates(ctx context.Context) (map[string]*store.StoredRoleTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*store.StoredRoleTemplate)
	for k, v := range s.roleTemplates {
		result[k] = v
	}
	return result, nil
}

// SaveRoleTemplate saves a role template.
func (s *Store) SaveRoleTemplate(ctx context.Context, template *store.StoredRoleTemplate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roleTemplates[template.Key] = template
	return nil
}

// SaveAPIKey saves an API key.
func (s *Store) SaveAPIKey(ctx context.Context, key *store.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys[key.ID] = key
	return nil
}

// GetAPIKeyByHash retrieves an API key by prefix and hash.
func (s *Store) GetAPIKeyByHash(ctx context.Context, prefix string, keyHash string) (*store.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range s.apiKeys {
		if key.Prefix == prefix && key.KeyHash == keyHash {
			return key, nil
		}
	}
	return nil, nil
}

// GetAPIKeysByUser retrieves all API keys for a user.
func (s *Store) GetAPIKeysByUser(ctx context.Context, userID string) ([]*store.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*store.APIKey
	for _, key := range s.apiKeys {
		if key.UserID == userID {
			result = append(result, key)
		}
	}
	return result, nil
}

// RevokeAPIKey revokes an API key.
func (s *Store) RevokeAPIKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, ok := s.apiKeys[id]; ok {
		now := time.Now()
		key.RevokedAt = &now
	}
	return nil
}

// DeleteExpiredAPIKeys removes expired API keys.
func (s *Store) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	now := time.Now()
	for id, key := range s.apiKeys {
		if key.ExpiresAt != nil && key.ExpiresAt.Before(now) {
			delete(s.apiKeys, id)
			count++
		}
	}
	return count, nil
}

// Verify Store implements store.Store interface
var _ store.Store = (*Store)(nil)
