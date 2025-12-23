-- name: SelectRoleTemplates
SELECT key, permissions, permission_hash, version, updated_at FROM goauth_role_templates;

-- name: UpsertRoleTemplate
INSERT INTO goauth_role_templates (key, permissions, permission_hash, version, updated_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (key) DO UPDATE SET
    permissions = EXCLUDED.permissions,
    permission_hash = EXCLUDED.permission_hash,
    version = EXCLUDED.version,
    updated_at = EXCLUDED.updated_at;
