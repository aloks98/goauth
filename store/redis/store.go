// Package redis provides Redis storage for goauth.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aloks98/goauth/store"
)

// Key prefixes for Redis storage.
const (
	prefixRefreshToken   = "goauth:refresh_token:"
	prefixTokenFamily    = "goauth:token_family:"
	prefixUserTokens     = "goauth:user_tokens:"
	prefixBlacklist      = "goauth:blacklist:"
	prefixUserPerms      = "goauth:user_perms:"
	prefixUsersByRole    = "goauth:users_by_role:"
	prefixRoleTemplate   = "goauth:role_template:"
	prefixRoleTemplates  = "goauth:role_templates"
	prefixAPIKey         = "goauth:api_key:"
	prefixAPIKeyByHash   = "goauth:api_key_hash:"
	prefixUserAPIKeys    = "goauth:user_api_keys:"
	prefixAPIKeyExpiries = "goauth:api_key_expiries"
)

// Store implements store.Store using Redis.
type Store struct {
	client redis.UniversalClient
}

// Config holds Redis store configuration.
type Config struct {
	// Client is an existing Redis client.
	// If provided, other options are ignored.
	Client redis.UniversalClient

	// Addr is the Redis server address (host:port).
	Addr string

	// Password is the Redis password.
	Password string

	// DB is the Redis database number.
	DB int

	// PoolSize is the maximum number of connections.
	PoolSize int
}

// New creates a new Redis store.
func New(cfg *Config) (*Store, error) {
	var client redis.UniversalClient

	if cfg.Client != nil {
		client = cfg.Client
	} else {
		opts := &redis.Options{
			Addr:     cfg.Addr,
			Password: cfg.Password,
			DB:       cfg.DB,
		}
		if cfg.PoolSize > 0 {
			opts.PoolSize = cfg.PoolSize
		}
		client = redis.NewClient(opts)
	}

	return &Store{client: client}, nil
}

// Close closes the Redis connection.
func (s *Store) Close() error {
	return s.client.Close()
}

// Ping verifies the Redis connection is alive.
func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// Migrate is a no-op for Redis as it doesn't require schema migration.
func (s *Store) Migrate(ctx context.Context) error {
	return nil
}

// SaveRefreshToken persists a refresh token.
func (s *Store) SaveRefreshToken(ctx context.Context, token *store.RefreshToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Second // Minimum TTL
	}

	pipe := s.client.Pipeline()

	// Store token
	pipe.Set(ctx, prefixRefreshToken+token.ID, data, ttl)

	// Add to family set
	pipe.SAdd(ctx, prefixTokenFamily+token.FamilyID, token.ID)
	pipe.Expire(ctx, prefixTokenFamily+token.FamilyID, ttl)

	// Add to user's tokens set
	pipe.SAdd(ctx, prefixUserTokens+token.UserID, token.ID)
	pipe.Expire(ctx, prefixUserTokens+token.UserID, ttl)

	_, err = pipe.Exec(ctx)
	return err
}

// GetRefreshToken retrieves a refresh token by JTI.
func (s *Store) GetRefreshToken(ctx context.Context, jti string) (*store.RefreshToken, error) {
	data, err := s.client.Get(ctx, prefixRefreshToken+jti).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var token store.RefreshToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (s *Store) RevokeRefreshToken(ctx context.Context, jti string, replacedBy string) error {
	token, err := s.GetRefreshToken(ctx, jti)
	if err != nil {
		return err
	}
	if token == nil {
		return nil // Token doesn't exist
	}

	now := time.Now()
	token.RevokedAt = &now
	if replacedBy != "" {
		token.ReplacedBy = &replacedBy
	}

	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	// Keep the same TTL
	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Second
	}

	return s.client.Set(ctx, prefixRefreshToken+jti, data, ttl).Err()
}

// RevokeTokenFamily revokes all tokens in a family.
func (s *Store) RevokeTokenFamily(ctx context.Context, familyID string) error {
	tokenIDs, err := s.client.SMembers(ctx, prefixTokenFamily+familyID).Result()
	if err != nil {
		return err
	}

	for _, jti := range tokenIDs {
		if err := s.RevokeRefreshToken(ctx, jti, ""); err != nil {
			return err
		}
	}

	return nil
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user.
func (s *Store) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	tokenIDs, err := s.client.SMembers(ctx, prefixUserTokens+userID).Result()
	if err != nil {
		return err
	}

	for _, jti := range tokenIDs {
		if err := s.RevokeRefreshToken(ctx, jti, ""); err != nil {
			return err
		}
	}

	return nil
}

// DeleteExpiredRefreshTokens removes expired refresh tokens.
// Redis handles this automatically via TTL, so this is a no-op.
func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	return 0, nil
}

// AddToBlacklist adds an access token JTI to the blacklist.
func (s *Store) AddToBlacklist(ctx context.Context, jti string, expiresAt int64) error {
	ttl := time.Until(time.Unix(expiresAt, 0))
	if ttl <= 0 {
		return nil // Already expired
	}

	return s.client.Set(ctx, prefixBlacklist+jti, "1", ttl).Err()
}

// IsBlacklisted checks if an access token JTI is blacklisted.
func (s *Store) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	exists, err := s.client.Exists(ctx, prefixBlacklist+jti).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// DeleteExpiredBlacklistEntries removes expired blacklist entries.
// Redis handles this automatically via TTL, so this is a no-op.
func (s *Store) DeleteExpiredBlacklistEntries(ctx context.Context) (int64, error) {
	return 0, nil
}

// GetUserPermissions retrieves user permissions.
func (s *Store) GetUserPermissions(ctx context.Context, userID string) (*store.UserPermissions, error) {
	data, err := s.client.Get(ctx, prefixUserPerms+userID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var perms store.UserPermissions
	if err := json.Unmarshal(data, &perms); err != nil {
		return nil, err
	}

	return &perms, nil
}

// SaveUserPermissions creates or updates user permissions.
func (s *Store) SaveUserPermissions(ctx context.Context, perms *store.UserPermissions) error {
	data, err := json.Marshal(perms)
	if err != nil {
		return err
	}

	pipe := s.client.Pipeline()

	// Store permissions
	pipe.Set(ctx, prefixUserPerms+perms.UserID, data, 0)

	// Add to role's users set for batch updates
	pipe.SAdd(ctx, prefixUsersByRole+perms.RoleLabel, perms.UserID)

	_, err = pipe.Exec(ctx)
	return err
}

// DeleteUserPermissions removes user permissions.
func (s *Store) DeleteUserPermissions(ctx context.Context, userID string) error {
	// Get current permissions to remove from role set
	perms, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return err
	}

	pipe := s.client.Pipeline()
	pipe.Del(ctx, prefixUserPerms+userID)

	if perms != nil {
		pipe.SRem(ctx, prefixUsersByRole+perms.RoleLabel, userID)
	}

	_, err = pipe.Exec(ctx)
	return err
}

// UpdateUsersWithRole updates all users with a specific role.
func (s *Store) UpdateUsersWithRole(ctx context.Context, roleLabel string, permissions []string, newVersion int) (int64, error) {
	userIDs, err := s.client.SMembers(ctx, prefixUsersByRole+roleLabel).Result()
	if err != nil {
		return 0, err
	}

	var updated int64
	for _, userID := range userIDs {
		perms, err := s.GetUserPermissions(ctx, userID)
		if err != nil {
			return updated, err
		}
		if perms == nil || perms.RoleLabel != roleLabel {
			continue
		}

		perms.Permissions = permissions
		perms.PermissionVersion = newVersion
		perms.UpdatedAt = time.Now()

		if err := s.SaveUserPermissions(ctx, perms); err != nil {
			return updated, err
		}
		updated++
	}

	return updated, nil
}

// GetRoleTemplates retrieves all role templates.
func (s *Store) GetRoleTemplates(ctx context.Context) (map[string]*store.StoredRoleTemplate, error) {
	keys, err := s.client.SMembers(ctx, prefixRoleTemplates).Result()
	if err != nil {
		return nil, err
	}

	templates := make(map[string]*store.StoredRoleTemplate)

	for _, key := range keys {
		data, err := s.client.Get(ctx, prefixRoleTemplate+key).Bytes()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			return nil, err
		}

		var template store.StoredRoleTemplate
		if err := json.Unmarshal(data, &template); err != nil {
			return nil, err
		}

		templates[key] = &template
	}

	return templates, nil
}

// SaveRoleTemplate saves a role template.
func (s *Store) SaveRoleTemplate(ctx context.Context, template *store.StoredRoleTemplate) error {
	data, err := json.Marshal(template)
	if err != nil {
		return err
	}

	pipe := s.client.Pipeline()
	pipe.Set(ctx, prefixRoleTemplate+template.Key, data, 0)
	pipe.SAdd(ctx, prefixRoleTemplates, template.Key)

	_, err = pipe.Exec(ctx)
	return err
}

// SaveAPIKey saves an API key.
func (s *Store) SaveAPIKey(ctx context.Context, key *store.APIKey) error {
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}

	var ttl time.Duration
	if key.ExpiresAt != nil {
		ttl = time.Until(*key.ExpiresAt)
		if ttl <= 0 {
			return nil // Already expired
		}
	}

	pipe := s.client.Pipeline()

	// Store key by ID
	pipe.Set(ctx, prefixAPIKey+key.ID, data, ttl)

	// Store hash lookup
	hashKey := prefixAPIKeyByHash + key.Prefix + ":" + key.KeyHash
	pipe.Set(ctx, hashKey, key.ID, ttl)

	// Add to user's keys set
	pipe.SAdd(ctx, prefixUserAPIKeys+key.UserID, key.ID)

	// Track expiry for cleanup
	if key.ExpiresAt != nil {
		pipe.ZAdd(ctx, prefixAPIKeyExpiries, redis.Z{
			Score:  float64(key.ExpiresAt.Unix()),
			Member: key.ID,
		})
	}

	_, err = pipe.Exec(ctx)
	return err
}

// GetAPIKeyByHash retrieves an API key by prefix and hash.
func (s *Store) GetAPIKeyByHash(ctx context.Context, prefix, keyHash string) (*store.APIKey, error) {
	hashKey := prefixAPIKeyByHash + prefix + ":" + keyHash
	keyID, err := s.client.Get(ctx, hashKey).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	data, err := s.client.Get(ctx, prefixAPIKey+keyID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var key store.APIKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}

	return &key, nil
}

// GetAPIKeysByUser retrieves all API keys for a user.
func (s *Store) GetAPIKeysByUser(ctx context.Context, userID string) ([]*store.APIKey, error) {
	keyIDs, err := s.client.SMembers(ctx, prefixUserAPIKeys+userID).Result()
	if err != nil {
		return nil, err
	}

	keys := make([]*store.APIKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		data, err := s.client.Get(ctx, prefixAPIKey+keyID).Bytes()
		if errors.Is(err, redis.Nil) {
			// Key expired, remove from set
			s.client.SRem(ctx, prefixUserAPIKeys+userID, keyID)
			continue
		}
		if err != nil {
			return nil, err
		}

		var key store.APIKey
		if err := json.Unmarshal(data, &key); err != nil {
			return nil, err
		}

		keys = append(keys, &key)
	}

	return keys, nil
}

// RevokeAPIKey revokes an API key.
func (s *Store) RevokeAPIKey(ctx context.Context, id string) error {
	data, err := s.client.Get(ctx, prefixAPIKey+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return err
	}

	var key store.APIKey
	if err := json.Unmarshal(data, &key); err != nil {
		return err
	}

	now := time.Now()
	key.RevokedAt = &now

	newData, err := json.Marshal(&key)
	if err != nil {
		return err
	}

	// Get remaining TTL
	ttl, err := s.client.TTL(ctx, prefixAPIKey+id).Result()
	if err != nil {
		return err
	}
	if ttl < 0 {
		ttl = 0 // No expiry
	}

	return s.client.Set(ctx, prefixAPIKey+id, newData, ttl).Err()
}

// DeleteExpiredAPIKeys removes expired API keys.
// Redis handles most of this via TTL, but we clean up the sorted set.
func (s *Store) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	now := float64(time.Now().Unix())

	// Remove expired entries from the sorted set
	result, err := s.client.ZRemRangeByScore(ctx, prefixAPIKeyExpiries, "-inf", formatFloat(now)).Result()
	if err != nil {
		return 0, err
	}

	return result, nil
}

// formatFloat formats a float64 for Redis.
func formatFloat(f float64) string {
	return strconv(f)
}

// strconv is a simple float to string conversion.
func strconv(f float64) string {
	// Simple implementation for sorted set scores
	i := int64(f)
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// Ensure Store implements store.Store.
var _ store.Store = (*Store)(nil)
