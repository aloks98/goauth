# Database Schema

## Overview

GoAuth creates and manages the following tables. All table names can be prefixed using `WithTablePrefix()`.

### Tables by Mode

| Table | Simple Mode | RBAC Mode |
|-------|-------------|-----------|
| `auth_refresh_tokens` | ✅ Created | ✅ Created |
| `auth_token_blacklist` | ✅ Created | ✅ Created |
| `auth_api_keys` | ✅ Created | ✅ Created |
| `auth_user_permissions` | ❌ Skipped | ✅ Created |
| `auth_role_templates` | ❌ Skipped | ✅ Created |
| `auth_role_sync_log` | ❌ Skipped | ✅ Created |

## Core Tables (All Modes)

## Tables

### auth_refresh_tokens

Stores refresh tokens for rotation and theft detection.

```sql
CREATE TABLE auth_refresh_tokens (
    id           VARCHAR(36) PRIMARY KEY,          -- UUID
    user_id      VARCHAR(255) NOT NULL,
    family_id    VARCHAR(36) NOT NULL,             -- Groups related tokens
    token_hash   VARCHAR(64) NOT NULL,             -- SHA256 of token
    issued_at    TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    revoked_at   TIMESTAMP,                        -- NULL if active
    replaced_by  VARCHAR(36),                      -- JTI of replacement token
    
    INDEX idx_refresh_user_id (user_id),
    INDEX idx_refresh_family_id (family_id),
    INDEX idx_refresh_expires_at (expires_at)
);
```

| Column | Description |
|--------|-------------|
| `id` | Unique token identifier (JTI) |
| `user_id` | Owner of the token |
| `family_id` | Groups tokens from same login session |
| `token_hash` | SHA256 hash of the actual token |
| `issued_at` | When token was created |
| `expires_at` | When token expires |
| `revoked_at` | When token was revoked (NULL if active) |
| `replaced_by` | JTI of the new token after rotation |

### auth_token_blacklist

Stores blacklisted access token JTIs for instant revocation.

```sql
CREATE TABLE auth_token_blacklist (
    jti         VARCHAR(36) PRIMARY KEY,
    expires_at  TIMESTAMP NOT NULL,
    
    INDEX idx_blacklist_expires_at (expires_at)
);
```

| Column | Description |
|--------|-------------|
| `jti` | Token's unique identifier |
| `expires_at` | When entry can be removed (matches token expiry) |

---

## RBAC Tables (Only Created When RBAC Enabled)

### auth_user_permissions

Stores user-level permissions.

```sql
CREATE TABLE auth_user_permissions (
    user_id             VARCHAR(255) PRIMARY KEY,
    role_label          VARCHAR(50) NOT NULL,       -- "editor", "custom", etc.
    base_role           VARCHAR(50),                -- Original assigned role
    permissions         TEXT[] NOT NULL,            -- Array of permission strings
    permission_version  INT NOT NULL DEFAULT 1,
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_by          VARCHAR(255),               -- Who made the change
    
    INDEX idx_user_perms_role_label (role_label),
    INDEX idx_user_perms_updated_at (updated_at)
);
```

| Column | Description |
|--------|-------------|
| `user_id` | User identifier (from your app) |
| `role_label` | Current role name or "custom" |
| `base_role` | Original role assigned |
| `permissions` | Array of permission strings |
| `permission_version` | Incremented on each change |
| `updated_at` | Last modification time |
| `updated_by` | User who made the change |

### auth_role_templates

Stores role template snapshots for sync comparison.

```sql
CREATE TABLE auth_role_templates (
    role_key         VARCHAR(50) PRIMARY KEY,
    name             VARCHAR(100) NOT NULL,
    description      VARCHAR(255),
    permissions      TEXT[] NOT NULL,
    permissions_hash VARCHAR(64) NOT NULL,        -- For quick comparison
    updated_at       TIMESTAMP NOT NULL DEFAULT NOW()
);
```

| Column | Description |
|--------|-------------|
| `role_key` | Role identifier (e.g., "editor") |
| `name` | Display name |
| `description` | Role description |
| `permissions` | Array of permissions |
| `permissions_hash` | SHA256 of sorted permissions |
| `updated_at` | When template was last synced |

### auth_role_sync_log

Audit log for role template syncs.

```sql
CREATE TABLE auth_role_sync_log (
    id               VARCHAR(36) PRIMARY KEY,
    role_key         VARCHAR(50) NOT NULL,
    old_permissions  TEXT[],
    new_permissions  TEXT[] NOT NULL,
    users_affected   INT NOT NULL,
    synced_at        TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_sync_log_role_key (role_key),
    INDEX idx_sync_log_synced_at (synced_at)
);
```

| Column | Description |
|--------|-------------|
| `id` | Log entry UUID |
| `role_key` | Role that was synced |
| `old_permissions` | Previous permissions |
| `new_permissions` | New permissions |
| `users_affected` | Number of users updated |
| `synced_at` | When sync occurred |

### auth_api_keys

Stores API keys.

```sql
CREATE TABLE auth_api_keys (
    id           VARCHAR(36) PRIMARY KEY,
    user_id      VARCHAR(255) NOT NULL,
    prefix       VARCHAR(20) NOT NULL,            -- e.g., "sk_live"
    key_hash     VARCHAR(64) NOT NULL,            -- SHA256 of key
    name         VARCHAR(255),                    -- User-friendly name
    scopes       TEXT[],                          -- Allowed permissions
    last_used_at TIMESTAMP,
    expires_at   TIMESTAMP,                       -- NULL = never expires
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMP,
    
    INDEX idx_api_keys_user_id (user_id),
    INDEX idx_api_keys_prefix (prefix),
    UNIQUE INDEX idx_api_keys_prefix_hash (prefix, key_hash)
);
```

| Column | Description |
|--------|-------------|
| `id` | Key UUID |
| `user_id` | Owner of the key |
| `prefix` | Key prefix (e.g., "sk_live") |
| `key_hash` | SHA256 of the secret part |
| `name` | Human-readable name |
| `scopes` | Allowed permissions (NULL = all user's permissions) |
| `last_used_at` | Last time key was used |
| `expires_at` | Expiration (NULL = never) |
| `created_at` | Creation time |
| `revoked_at` | Revocation time (NULL if active) |

---

## Dialect-Specific Variations

### PostgreSQL

Uses native `TEXT[]` arrays and `TIMESTAMP WITH TIME ZONE`.

```sql
permissions TEXT[] NOT NULL
updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
```

### MySQL

Uses JSON for arrays.

```sql
permissions JSON NOT NULL
updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
```

### SQLite

Uses JSON text for arrays.

```sql
permissions TEXT NOT NULL  -- JSON array as string
updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
```

---

## Indexes

### Performance Indexes

| Table | Index | Purpose |
|-------|-------|---------|
| `auth_refresh_tokens` | `idx_refresh_user_id` | Find all tokens for a user |
| `auth_refresh_tokens` | `idx_refresh_family_id` | Find tokens in a family |
| `auth_refresh_tokens` | `idx_refresh_expires_at` | Cleanup expired tokens |
| `auth_token_blacklist` | `idx_blacklist_expires_at` | Cleanup expired entries |
| `auth_user_permissions` | `idx_user_perms_role_label` | Sync users with a role |
| `auth_api_keys` | `idx_api_keys_user_id` | List user's keys |
| `auth_api_keys` | `idx_api_keys_prefix_hash` | Validate key (unique) |

---

## Auto-Migration

When `WithAutoMigrate(true)` is enabled, GoAuth:

1. Checks if tables exist
2. Creates missing tables
3. Adds missing columns (non-destructive)
4. Creates missing indexes

**Note:** Auto-migration does NOT:
- Drop columns
- Modify column types
- Drop tables

For production, consider managing migrations manually.

---

## Cleanup

Background worker periodically removes:

1. Expired refresh tokens (`expires_at < NOW()`)
2. Expired blacklist entries (`expires_at < NOW()`)
3. Expired API keys (`expires_at < NOW() AND expires_at IS NOT NULL`)

Cleanup interval is configurable via `WithCleanupInterval()`.

---

## Redis Schema

When using Redis store:

```
goauth:blacklist:{jti}           -> "1" (with TTL)
goauth:refresh:{jti}             -> JSON (RefreshToken)
goauth:refresh:user:{user_id}    -> SET of JTIs
goauth:refresh:family:{family_id} -> SET of JTIs
goauth:perms:{user_id}           -> JSON (UserPermissions)
goauth:perms:version:{user_id}   -> INT (permission_version)
goauth:roles                     -> HASH (role_key -> JSON)
goauth:apikey:{prefix}:{hash}    -> JSON (APIKey)
goauth:apikey:user:{user_id}     -> SET of key IDs
```
