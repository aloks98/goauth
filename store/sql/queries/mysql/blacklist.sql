-- name: InsertBlacklist
INSERT IGNORE INTO goauth_blacklist (jti, expires_at) VALUES (?, ?);

-- name: SelectBlacklist
SELECT 1 FROM goauth_blacklist WHERE jti = ?;

-- name: DeleteExpiredBlacklistEntries
DELETE FROM goauth_blacklist WHERE expires_at < ?;
