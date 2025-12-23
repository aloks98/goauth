-- name: InsertRefreshToken
INSERT INTO goauth_refresh_tokens (id, user_id, family_id, token_hash, issued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: SelectRefreshToken
SELECT id, user_id, family_id, token_hash, issued_at, expires_at, revoked_at, replaced_by
FROM goauth_refresh_tokens WHERE id = ?;

-- name: RevokeRefreshToken
UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, replaced_by = ? WHERE id = ?;

-- name: RevokeTokenFamily
UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE family_id = ? AND revoked_at IS NULL;

-- name: RevokeAllUserRefreshTokens
UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL;

-- name: DeleteExpiredRefreshTokens
DELETE FROM goauth_refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP;
