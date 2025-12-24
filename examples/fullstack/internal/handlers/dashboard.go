package handlers

// ShowDashboard renders the dashboard page.
func (h *Handler) ShowDashboard(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.Redirect("/login", 302)
	}

	// Get user info
	user, err := h.app.Users.GetByID(c.Context(), userID)
	if err != nil {
		return c.Redirect("/login", 302)
	}

	// Get user permissions and role from RBAC
	var perms []string
	role := "user" // default
	userPerms, err := h.app.Auth.GetUserPermissions(c.Context(), userID)
	if err == nil && userPerms != nil {
		perms = userPerms.Permissions
		if userPerms.RoleLabel != "" {
			role = userPerms.RoleLabel
		}
	}

	userData := &UserData{
		ID:          user.ID,
		Email:       user.Email,
		Name:        user.Name,
		Role:        role,
		Permissions: perms,
	}

	return c.Render("pages/dashboard.html", PageData{
		Title:  "Dashboard",
		Active: "dashboard",
		User:   userData,
	})
}
