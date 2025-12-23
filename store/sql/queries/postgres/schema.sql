-- Refresh tokens table
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

-- Blacklist table
CREATE TABLE IF NOT EXISTS goauth_blacklist (
    jti VARCHAR(64) PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_blacklist_expires_at ON goauth_blacklist(expires_at);

-- User permissions table
CREATE TABLE IF NOT EXISTS goauth_user_permissions (
    user_id VARCHAR(255) PRIMARY KEY,
    role_label VARCHAR(64) NOT NULL,
    base_role VARCHAR(64),
    permissions TEXT NOT NULL,
    permission_version INT NOT NULL DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_permissions_role_label ON goauth_user_permissions(role_label);

-- Role templates table
CREATE TABLE IF NOT EXISTS goauth_role_templates (
    key VARCHAR(64) PRIMARY KEY,
    permissions TEXT NOT NULL,
    permission_hash VARCHAR(64) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API keys table
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
