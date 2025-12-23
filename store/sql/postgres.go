package sql

func getPostgreSQLQueries() *dialectQueries {
	return &dialectQueries{
		placeholder: postgresPlaceholder,

		// Schema creation
		createRefreshTokensTable: `
			CREATE TABLE IF NOT EXISTS goauth_refresh_tokens (
				id VARCHAR(64) PRIMARY KEY,
				user_id VARCHAR(255) NOT NULL,
				family_id VARCHAR(64) NOT NULL,
				token_hash VARCHAR(64) NOT NULL,
				issued_at TIMESTAMP NOT NULL,
				expires_at TIMESTAMP NOT NULL,
				revoked_at TIMESTAMP,
				replaced_by VARCHAR(64),
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON goauth_refresh_tokens(user_id);
			CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON goauth_refresh_tokens(family_id);
			CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON goauth_refresh_tokens(expires_at);
		`,

		createBlacklistTable: `
			CREATE TABLE IF NOT EXISTS goauth_blacklist (
				jti VARCHAR(64) PRIMARY KEY,
				expires_at BIGINT NOT NULL,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_blacklist_expires_at ON goauth_blacklist(expires_at);
		`,

		createUserPermissionsTable: `
			CREATE TABLE IF NOT EXISTS goauth_user_permissions (
				user_id VARCHAR(255) PRIMARY KEY,
				role_label VARCHAR(64) NOT NULL,
				base_role VARCHAR(64),
				permissions TEXT NOT NULL,
				permission_version INT NOT NULL DEFAULT 1,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_user_permissions_role_label ON goauth_user_permissions(role_label);
		`,

		createRoleTemplatesTable: `
			CREATE TABLE IF NOT EXISTS goauth_role_templates (
				key VARCHAR(64) PRIMARY KEY,
				permissions TEXT NOT NULL,
				permission_hash VARCHAR(64) NOT NULL,
				version INT NOT NULL DEFAULT 1,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			);
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
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				expires_at TIMESTAMP,
				last_used_at TIMESTAMP,
				revoked_at TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON goauth_api_keys(user_id);
			CREATE INDEX IF NOT EXISTS idx_api_keys_prefix_hash ON goauth_api_keys(prefix, key_hash);
			CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON goauth_api_keys(expires_at);
		`,

		// Refresh tokens
		insertRefreshToken: `
			INSERT INTO goauth_refresh_tokens (id, user_id, family_id, token_hash, issued_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)
		`,

		selectRefreshToken: `
			SELECT id, user_id, family_id, token_hash, issued_at, expires_at, revoked_at, replaced_by
			FROM goauth_refresh_tokens WHERE id = $1
		`,

		revokeRefreshToken: `
			UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, replaced_by = $2 WHERE id = $1
		`,

		revokeTokenFamily: `
			UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE family_id = $1 AND revoked_at IS NULL
		`,

		revokeAllUserRefreshTokens: `
			UPDATE goauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND revoked_at IS NULL
		`,

		deleteExpiredRefreshTokens: `
			DELETE FROM goauth_refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP
		`,

		// Blacklist
		insertBlacklist: `
			INSERT INTO goauth_blacklist (jti, expires_at) VALUES ($1, $2)
			ON CONFLICT (jti) DO NOTHING
		`,

		selectBlacklist: `
			SELECT 1 FROM goauth_blacklist WHERE jti = $1
		`,

		deleteExpiredBlacklistEntries: `
			DELETE FROM goauth_blacklist WHERE expires_at < $1
		`,

		// User permissions
		selectUserPermissions: `
			SELECT user_id, role_label, base_role, permissions, permission_version, updated_at
			FROM goauth_user_permissions WHERE user_id = $1
		`,

		upsertUserPermissions: `
			INSERT INTO goauth_user_permissions (user_id, role_label, base_role, permissions, permission_version, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (user_id) DO UPDATE SET
				role_label = EXCLUDED.role_label,
				base_role = EXCLUDED.base_role,
				permissions = EXCLUDED.permissions,
				permission_version = EXCLUDED.permission_version,
				updated_at = EXCLUDED.updated_at
		`,

		deleteUserPermissions: `
			DELETE FROM goauth_user_permissions WHERE user_id = $1
		`,

		updateUsersWithRole: `
			UPDATE goauth_user_permissions
			SET permissions = $2, permission_version = $3, updated_at = CURRENT_TIMESTAMP
			WHERE role_label = $1
		`,

		// Role templates
		selectRoleTemplates: `
			SELECT key, permissions, permission_hash, version, updated_at FROM goauth_role_templates
		`,

		upsertRoleTemplate: `
			INSERT INTO goauth_role_templates (key, permissions, permission_hash, version, updated_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (key) DO UPDATE SET
				permissions = EXCLUDED.permissions,
				permission_hash = EXCLUDED.permission_hash,
				version = EXCLUDED.version,
				updated_at = EXCLUDED.updated_at
		`,

		// API keys
		insertAPIKey: `
			INSERT INTO goauth_api_keys (id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`,

		selectAPIKeyByHash: `
			SELECT id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at, last_used_at, revoked_at
			FROM goauth_api_keys WHERE prefix = $1 AND key_hash = $2
		`,

		selectAPIKeysByUser: `
			SELECT id, user_id, name, prefix, key_hash, hint, scopes, created_at, expires_at, last_used_at, revoked_at
			FROM goauth_api_keys WHERE user_id = $1 ORDER BY created_at DESC
		`,

		revokeAPIKey: `
			UPDATE goauth_api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1
		`,

		deleteExpiredAPIKeys: `
			DELETE FROM goauth_api_keys WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP
		`,
	}
}
