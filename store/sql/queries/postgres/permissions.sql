-- name: SelectUserPermissions
SELECT user_id, role_label, base_role, permissions, permission_version, updated_at
FROM goauth_user_permissions WHERE user_id = $1;

-- name: UpsertUserPermissions
INSERT INTO goauth_user_permissions (user_id, role_label, base_role, permissions, permission_version, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_id) DO UPDATE SET
    role_label = EXCLUDED.role_label,
    base_role = EXCLUDED.base_role,
    permissions = EXCLUDED.permissions,
    permission_version = EXCLUDED.permission_version,
    updated_at = EXCLUDED.updated_at;

-- name: DeleteUserPermissions
DELETE FROM goauth_user_permissions WHERE user_id = $1;

-- name: UpdateUsersWithRole
UPDATE goauth_user_permissions
SET permissions = $2, permission_version = $3, updated_at = CURRENT_TIMESTAMP
WHERE role_label = $1;
