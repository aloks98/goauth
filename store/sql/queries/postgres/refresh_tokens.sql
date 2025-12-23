-- name: InsertRefreshToken
INSERT INTO goauth_refresh_tokens (id, user_id, family_id, token_hash, issued_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: SelectRefreshToken
SELECT id, user_id, family_id, token_hash, issued_at, expires_at, revoked_at, replaced_by
FROM goauth_refresh_tokens WHERE id = $1;

-- name: RevokeRefreshToken
UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, replaced_by = $2 WHERE id = $1;

-- name: RevokeTokenFamily
UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE family_id = $1 AND revoked_at IS NULL;

-- name: RevokeAllUserRefreshTokens
UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredRefreshTokens
DELETE FROM goauth_refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP;
