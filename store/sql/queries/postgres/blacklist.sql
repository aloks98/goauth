-- name: InsertBlacklist
INSERT INTO goauth_blacklist (jti, expires_at) VALUES ($1, $2)
ON CONFLICT (jti) DO NOTHING;

-- name: SelectBlacklist
SELECT 1 FROM goauth_blacklist WHERE jti = $1;

-- name: DeleteExpiredBlacklistEntries
DELETE FROM goauth_blacklist WHERE expires_at < $1;
