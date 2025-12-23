-- Refresh tokens table
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

-- Blacklist table
CREATE TABLE IF NOT EXISTS goauth_blacklist (
    jti VARCHAR(64) PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- User permissions table
CREATE TABLE IF NOT EXISTS goauth_user_permissions (
    user_id VARCHAR(255) PRIMARY KEY,
    role_label VARCHAR(64) NOT NULL,
    base_role VARCHAR(64),
    permissions TEXT NOT NULL,
    permission_version INT NOT NULL DEFAULT 1,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_role_label (role_label)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Role templates table
CREATE TABLE IF NOT EXISTS goauth_role_templates (
    `key` VARCHAR(64) PRIMARY KEY,
    permissions TEXT NOT NULL,
    permission_hash VARCHAR(64) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- API keys table
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
