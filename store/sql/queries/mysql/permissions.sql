-- name: SelectUserPermissions
SELECT user_id, role_label, base_role, permissions, permission_version, updated_at
FROM goauth_user_permissions WHERE user_id = ?;

-- name: UpsertUserPermissions
INSERT INTO goauth_user_permissions (user_id, role_label, base_role, permissions, permission_version, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    role_label = VALUES(role_label),
    base_role = VALUES(base_role),
    permissions = VALUES(permissions),
    permission_version = VALUES(permission_version),
    updated_at = VALUES(updated_at);

-- name: DeleteUserPermissions
DELETE FROM goauth_user_permissions WHERE user_id = ?;

-- name: UpdateUsersWithRole
UPDATE goauth_user_permissions
SET permissions = ?, permission_version = ?, updated_at = CURRENT_TIMESTAMP
WHERE role_label = ?;
