package handlers

import (
	"net/http"
)

// AdminRoleData represents role data for admin templates.
type AdminRoleData struct {
	Key         string
	Name        string
	Description string
	Permissions []string
}

// ShowAdmin renders the admin page.
func (h *Handler) ShowAdmin(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.Redirect("/login", 302)
	}

	// Check if user has permission to view users or settings
	canViewUsers, _ := h.app.Auth.HasPermission(c.Context(), userID, "users:read")
	canViewSettings, _ := h.app.Auth.HasPermission(c.Context(), userID, "settings:read")

	if !canViewUsers && !canViewSettings {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Access denied. You need users:read or settings:read permission.",
		})
	}

	// Get user info for nav
	user, _ := h.app.Users.GetByID(c.Context(), userID)
	var userData *UserData
	if user != nil {
		// Get actual role from permissions
		role := "user"
		if perms, err := h.app.Auth.GetUserPermissions(c.Context(), userID); err == nil && perms != nil {
			if perms.RoleLabel != "" {
				role = perms.RoleLabel
			}
		}
		userData = &UserData{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
			Role:  role,
		}
	}

	// Get available roles
	roleTemplates := h.app.Auth.GetAllRoles()
	roles := make([]AdminRoleData, 0, len(roleTemplates))
	for _, tmpl := range roleTemplates {
		roles = append(roles, AdminRoleData{
			Key:         tmpl.Key,
			Name:        tmpl.Name,
			Description: tmpl.Description,
			Permissions: tmpl.Permissions,
		})
	}

	// Check additional permissions for UI
	canUpdateUsers, _ := h.app.Auth.HasPermission(c.Context(), userID, "users:update")
	canRevokeSessions, _ := h.app.Auth.HasPermission(c.Context(), userID, "sessions:revoke")

	return c.Render("pages/admin.html", map[string]interface{}{
		"Title":             "Admin",
		"Active":            "admin",
		"User":              userData,
		"Roles":             roles,
		"CanViewUsers":      canViewUsers,
		"CanUpdateUsers":    canUpdateUsers,
		"CanRevokeSessions": canRevokeSessions,
		"CanViewSettings":   canViewSettings,
	})
}

// ListUsers returns the list of all users for HTMX partial.
func (h *Handler) ListUsers(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Check if user has permission to view users
	canViewUsers, _ := h.app.Auth.HasPermission(c.Context(), userID, "users:read")
	if !canViewUsers {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden: users:read permission required"})
	}

	// Check additional permissions for UI controls
	canUpdateUsers, _ := h.app.Auth.HasPermission(c.Context(), userID, "users:update")
	canRevokeSessions, _ := h.app.Auth.HasPermission(c.Context(), userID, "sessions:revoke")

	users, _ := h.app.Users.List(c.Context())

	// Get available roles for dropdown (only if user can update)
	var roles []string
	if canUpdateUsers {
		roleTemplates := h.app.Auth.GetAllRoles()
		for _, tmpl := range roleTemplates {
			roles = append(roles, tmpl.Key)
		}
	}

	// Convert to template data with roles
	usersData := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		role := "" // no role by default
		if perms, err := h.app.Auth.GetUserPermissions(c.Context(), u.ID); err == nil && perms != nil {
			if perms.RoleLabel != "" {
				role = perms.RoleLabel
			}
		}

		usersData = append(usersData, map[string]interface{}{
			"ID":        u.ID,
			"Email":     u.Email,
			"Name":      u.Name,
			"Role":      role,
			"CreatedAt": u.CreatedAt,
		})
	}

	return c.RenderPartial("partials/users-list.html", map[string]interface{}{
		"Users":             usersData,
		"AvailableRoles":    roles,
		"CanUpdateUsers":    canUpdateUsers,
		"CanRevokeSessions": canRevokeSessions,
	})
}

// AdminAssignRole assigns a role to a user.
func (h *Handler) AdminAssignRole(c Context) error {
	adminID := c.UserID()
	if adminID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Check if user has permission to update users
	canUpdate, _ := h.app.Auth.HasPermission(c.Context(), adminID, "users:update")
	if !canUpdate {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Access denied. users:update permission required.",
		})
	}

	targetUserID := c.Param("id")
	if targetUserID == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "User ID is required",
		})
	}

	newRole := c.FormValue("role")
	if newRole == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Role is required",
		})
	}

	// Get user info for message
	user, err := h.app.Users.GetByID(c.Context(), targetUserID)
	if err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "User not found",
		})
	}

	// Assign the role
	if err := h.app.Auth.AssignRole(c.Context(), targetUserID, newRole); err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to assign role: " + err.Error(),
		})
	}

	// Trigger refresh of user list
	c.HXTrigger("user-role-changed")

	return c.RenderPartial("partials/flash.html", Flash{
		Type:    "success",
		Message: "Role '" + newRole + "' assigned to " + user.Name,
	})
}

// RevokeUserTokens revokes all tokens for a specific user.
func (h *Handler) RevokeUserTokens(c Context) error {
	adminID := c.UserID()
	if adminID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Check if user has permission to revoke sessions
	canRevoke, _ := h.app.Auth.HasPermission(c.Context(), adminID, "sessions:revoke")
	if !canRevoke {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Access denied. sessions:revoke permission required.",
		})
	}

	targetUserID := c.Param("id")
	if targetUserID == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "User ID is required",
		})
	}

	// Get user info for message
	user, err := h.app.Users.GetByID(c.Context(), targetUserID)
	if err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "User not found",
		})
	}

	// Revoke all tokens
	if err := h.app.Auth.RevokeAllUserTokens(c.Context(), targetUserID); err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to revoke tokens: " + err.Error(),
		})
	}

	return c.RenderPartial("partials/flash.html", Flash{
		Type:    "success",
		Message: "All tokens revoked for " + user.Name,
	})
}

// GetCleanupStats returns cleanup worker statistics.
func (h *Handler) GetCleanupStats(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Check if user has permission to view settings
	canView, _ := h.app.Auth.HasPermission(c.Context(), userID, "settings:read")
	if !canView {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden: settings:read permission required"})
	}

	// Get cleanup stats if available
	stats := h.app.GetCleanupStats()

	return c.JSON(http.StatusOK, stats)
}

// RunCleanup triggers a manual cleanup.
func (h *Handler) RunCleanup(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Check if user has permission to update settings
	canUpdate, _ := h.app.Auth.HasPermission(c.Context(), userID, "settings:update")
	if !canUpdate {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Access denied. settings:update permission required.",
		})
	}

	// Run cleanup
	if err := h.app.RunCleanup(c.Context()); err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Cleanup failed: " + err.Error(),
		})
	}

	return c.RenderPartial("partials/flash.html", Flash{
		Type:    "success",
		Message: "Cleanup completed successfully",
	})
}
