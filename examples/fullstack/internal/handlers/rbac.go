package handlers

import (
	"net/http"
	"strings"
)

// UserPermsData represents user permissions for templates.
type UserPermsData struct {
	RoleLabel         string
	BaseRole          string
	PermissionVersion int
	Permissions       []string
}

// RoleData represents a role for templates.
type RoleData struct {
	Key         string
	Name        string
	Description string
}

// ShowRBAC renders the RBAC demo page.
func (h *Handler) ShowRBAC(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.Redirect("/login", 302)
	}

	// Get user info for nav
	user, _ := h.app.Users.GetByID(c.Context(), userID)
	var userData *UserData
	var userPermsData *UserPermsData

	if user != nil {
		role := "user"
		var perms []string
		var permVersion int
		var baseRole string

		userPerms, err := h.app.Auth.GetUserPermissions(c.Context(), userID)
		if err == nil && userPerms != nil {
			perms = userPerms.Permissions
			permVersion = userPerms.PermissionVersion
			if userPerms.RoleLabel != "" {
				role = userPerms.RoleLabel
			}
			baseRole = userPerms.BaseRole
		}

		userData = &UserData{
			ID:          user.ID,
			Email:       user.Email,
			Name:        user.Name,
			Role:        role,
			Permissions: perms,
		}

		userPermsData = &UserPermsData{
			RoleLabel:         role,
			BaseRole:          baseRole,
			PermissionVersion: permVersion,
			Permissions:       perms,
		}
	}

	// Available roles
	roles := []RoleData{
		{Key: "admin", Name: "Admin", Description: "Full system access"},
		{Key: "user", Name: "User", Description: "Standard user access"},
		{Key: "viewer", Name: "Viewer", Description: "Read-only access"},
	}

	return c.Render("pages/rbac.html", map[string]interface{}{
		"Title":     "RBAC Demo",
		"Active":    "rbac",
		"User":      userData,
		"UserPerms": userPermsData,
		"Roles":     roles,
	})
}

// AssignRole assigns a role to the current user.
func (h *Handler) AssignRole(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	role := c.FormValue("role")
	if role == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Role is required",
		})
	}

	// Validate role (must be one of our defined roles)
	validRoles := map[string]bool{"admin": true, "user": true, "viewer": true}
	if !validRoles[role] {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Invalid role",
		})
	}

	if err := h.app.Auth.AssignRole(c.Context(), userID, role); err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to assign role: " + err.Error(),
		})
	}

	c.HXTrigger("permissions-changed")
	return c.RenderPartial("partials/flash.html", Flash{
		Type:    "success",
		Message: "Role '" + role + "' assigned successfully",
	})
}

// AddPermission adds a single permission to the current user.
func (h *Handler) AddPermission(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	permission := c.FormValue("permission")
	if permission == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Permission is required",
		})
	}

	permission = strings.TrimSpace(permission)

	if err := h.app.Auth.AddPermissions(c.Context(), userID, []string{permission}); err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to add permission: " + err.Error(),
		})
	}

	c.HXTrigger("permissions-changed")
	return c.RenderPartial("partials/flash.html", Flash{
		Type:    "success",
		Message: "Permission '" + permission + "' added successfully",
	})
}

// CheckPermission checks if the current user has a permission.
func (h *Handler) CheckPermission(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	permission := c.FormValue("permission")
	if permission == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Permission is required",
		})
	}

	hasPermission, _ := h.app.Auth.HasPermission(c.Context(), userID, permission)

	return c.RenderPartial("partials/check-result.html", map[string]interface{}{
		"Permission":    permission,
		"HasPermission": hasPermission,
	})
}

// GetPermissions returns the current user's permissions.
func (h *Handler) GetPermissions(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var perms []string
	userPerms, err := h.app.Auth.GetUserPermissions(c.Context(), userID)
	if err == nil && userPerms != nil {
		perms = userPerms.Permissions
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"permissions": perms,
	})
}
