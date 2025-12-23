package sql

func getMySQLQueries() *dialectQueries {
	return &dialectQueries{
		placeholder: mysqlPlaceholder,

		// Schema creation
		createRefreshTokensTable: `
			CREATE TABLE IF NOT EXISTS goauth_refresh_tokens (
				id VARCHAR(64) PRIMARY KEY,
				user_id VARCHAR(255) NOT NULL,
				family_id VARCHAR(64) NOT NULL,
				token_hash VARCHAR(64) NOT NULL,
				issued_at DATETIME NOT NULL,
				expires_at DATETIME NOT NULL,
				revoked_at DATETIME,
				replaced_by VARCHAR(64),
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				INDEX idx_user_id (user_id),
				INDEX idx_family_id (family_id),
				INDEX idx_expires_at (expires_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		`,

		createBlacklistTable: `
			CREATE TABLE IF NOT EXISTS goauth_blacklist (
				jti VARCHAR(64) PRIMARY KEY,
				expires_at BIGINT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				INDEX idx_expires_at (expires_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		`,

		createUserPermissionsTable: `
			CREATE TABLE IF NOT EXISTS goauth_user_permissions (
				user_id VARCHAR(255) PRIMARY KEY,
				role_label VARCHAR(64) NOT NULL,
				base_role VARCHAR(64),
				permissions TEXT NOT NULL,
				permission_version INT NOT NULL DEFAULT 1,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				INDEX idx_role_label (role_label)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		`,

		createRoleTemplatesTable: `
			CREATE TABLE IF NOT EXISTS goauth_role_templates (
				` + "`key`" + ` VARCHAR(64) PRIMARY KEY,
				permissions TEXT NOT NULL,
				permission_hash VARCHAR(64) NOT NULL,
				version INT NOT NULL DEFAULT 1,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		`,

		createAPIKeysTable: `
			CREATE TABLE IF NOT EXISTS goauth_api_keys (
				id VARCHAR(64) PRIMARY KEY,
				user_id VARCHAR(255) NOT NULL,
				name VARCHAR(255),
				prefix VARCHAR(32) NOT NULL,
				key_hash VARCHAR(64) NOT NULL,
				hint VARCHAR(8),
				scopes TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				expires_at DATETIME,
				last_used_at DATETIME,
				revoked_at DATETIME,
				INDEX idx_user_id (user_id),
				INDEX idx_prefix_hash (prefix, key_hash),
				INDEX idx_expires_at (expires_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		`,

		// Refresh tokens
		insertRefreshToken: `
			INSERT INTO goauth_refresh_tokens (id, user_id, family_id, token_hash, issued_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`,

		selectRefreshToken: `
			SELECT id, user_id, family_id, token_hash, issued_at, expires_at, revoked_at, replaced_by
			FROM goauth_refresh_tokens WHERE id = ?
		`,

		revokeRefreshToken: `
			UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, replaced_by = ? WHERE id = ?
		`,

		revokeTokenFamily: `
			UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE family_id = ? AND revoked_at IS NULL
		`,

		revokeAllUserRefreshTokens: `
			UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL
		`,

		deleteExpiredRefreshTokens: `
			DELETE FROM goauth_refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP
		`,

		// Blacklist
		insertBlacklist: `
			INSERT IGNORE INTO goauth_blacklist (jti, expires_at) VALUES (?, ?)
		`,

		selectBlacklist: `
			SELECT 1 FROM goauth_blacklist WHERE jti = ?
		`,

		deleteExpiredBlacklistEntries: `
			DELETE FROM goauth_blacklist WHERE expires_at < ?
		`,

		// User permissions
		selectUserPermissions: `
			SELECT user_id, role_label, base_role, permissions, permission_version, updated_at
			FROM goauth_user_permissions WHERE user_id = ?
		`,

		upsertUserPermissions: `
			INSERT INTO goauth_user_permissions (user_id, role_label, base_role, permissions, permission_version, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				role_label = VALUES(role_label),
				base_role = VALUES(base_role),
				permissions = VALUES(permissions),
				permission_version = VALUES(permission_version),
				updated_at = VALUES(updated_at)
		`,

		deleteUserPermissions: `
			DELETE FROM goauth_user_permissions WHERE user_id = ?
		`,

		updateUsersWithRole: `
			UPDATE goauth_user_permissions
			SET permissions = ?, permission_version = ?, updated_at = CURRENT_TIMESTAMP
			WHERE role_label = ?
		`,

		// Role templates
		selectRoleTemplates: `
			SELECT ` + "`key`" + `, permissions, permission_hash, version, updated_at FROM goauth_role_templates
		`,

		upsertRoleTemplate: `
			INSERT INTO goauth_role_templates (` + "`key`" + `, permissions, permission_hash, version, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				permissions = VALUES(permissions),
				permission_hash = VALUES(permission_hash),
				version = VALUES(version),
				updated_at = VALUES(updated_at)
		`,

		// API keys
		insertAPIKey: `
			INSERT INTO goauth_api_keys (id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,

		selectAPIKeyByHash: `
			SELECT id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at, last_used_at, revoked_at
			FROM goauth_api_keys WHERE prefix = ? AND key_hash = ?
		`,

		selectAPIKeysByUser: `
			SELECT id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at, last_used_at, revoked_at
			FROM goauth_api_keys WHERE user_id = ? ORDER BY created_at DESC
		`,

		revokeAPIKey: `
			UPDATE goauth_api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?
		`,

		deleteExpiredAPIKeys: `
			DELETE FROM goauth_api_keys WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP
		`,
	}
}
