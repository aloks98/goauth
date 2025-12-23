-- name: SelectRoleTemplates
SELECT `key`, permissions, permission_hash, version, updated_at FROM goauth_role_templates;

-- name: UpsertRoleTemplate
INSERT INTO goauth_role_templates (`key`, permissions, permission_hash, version, updated_at)
VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    permissions = VALUES(permissions),
    permission_hash = VALUES(permission_hash),
    version = VALUES(version),
    updated_at = VALUES(updated_at);
