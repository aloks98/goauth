-- name: InsertAPIKey
INSERT INTO goauth_api_keys (id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SelectAPIKeyByHash
SELECT id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at, last_used_at, revoked_at
FROM goauth_api_keys WHERE prefix = ? AND key_hash = ?;

-- name: SelectAPIKeysByUser
SELECT id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at, last_used_at, revoked_at
FROM goauth_api_keys WHERE user_id = ? ORDER BY created_at DESC;

-- name: RevokeAPIKey
UPDATE goauth_api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeleteExpiredAPIKeys
DELETE FROM goauth_api_keys WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP;
