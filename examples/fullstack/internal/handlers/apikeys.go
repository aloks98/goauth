package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/aloks98/goauth/apikey"
)

// APIKeyData represents an API key for templates.
type APIKeyData struct {
	ID        string
	Name      string
	KeyPrefix string
	Scopes    []string
	ExpiresAt *time.Time
	CreatedAt time.Time
	LastUsed  *time.Time
}

// ShowAPIKeys renders the API keys page.
func (h *Handler) ShowAPIKeys(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.Redirect("/login", 302)
	}

	// Get user info for nav
	user, _ := h.app.Users.GetByID(c.Context(), userID)
	var userData *UserData
	if user != nil {
		// Get role from permissions
		role := "user"
		userPerms, err := h.app.Auth.GetUserPermissions(c.Context(), userID)
		if err == nil && userPerms != nil && userPerms.RoleLabel != "" {
			role = userPerms.RoleLabel
		}
		userData = &UserData{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
			Role:  role,
		}
	}

	return c.Render("pages/apikeys.html", PageData{
		Title:  "API Keys",
		Active: "apikeys",
		User:   userData,
	})
}

// ShowCreateAPIKeyForm shows the create API key form modal.
func (h *Handler) ShowCreateAPIKeyForm(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	return c.RenderPartial("partials/apikey-form.html", nil)
}

// ListAPIKeys returns the list of API keys for HTMX partial.
func (h *Handler) ListAPIKeys(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	keys, err := h.app.Auth.ListAPIKeys(c.Context(), userID)
	if err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to load API keys",
		})
	}

	// Convert to template data
	keyData := make([]APIKeyData, 0, len(keys))
	for _, k := range keys {
		keyData = append(keyData, APIKeyData{
			ID:        k.ID,
			Name:      k.Name,
			KeyPrefix: k.Prefix + "_..." + k.Hint,
			Scopes:    k.Scopes,
			ExpiresAt: k.ExpiresAt,
			CreatedAt: k.CreatedAt,
			LastUsed:  k.LastUsedAt,
		})
	}

	return c.RenderPartial("partials/apikey-list.html", map[string]interface{}{
		"Keys": keyData,
	})
}

// CreateAPIKey creates a new API key.
func (h *Handler) CreateAPIKey(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	name := c.FormValue("name")
	scopesStr := c.FormValue("scopes")
	expiresIn := c.FormValue("expires_in")

	if name == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Name is required",
		})
	}

	// Parse scopes
	var scopes []string
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, ",")
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}

	// Build options
	opts := &apikey.CreateKeyOptions{
		Name:   name,
		Scopes: scopes,
	}

	// Parse expiration
	switch expiresIn {
	case "30d":
		opts.TTL = 30 * 24 * time.Hour
	case "90d":
		opts.TTL = 90 * 24 * time.Hour
	case "1y":
		opts.TTL = 365 * 24 * time.Hour
		// "never" = no expiration option
	}

	// Create the key
	result, err := h.app.Auth.CreateAPIKey(c.Context(), userID, opts)
	if err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to create API key",
		})
	}

	// Trigger refresh of key list
	c.HXTrigger("apikey-created")

	// Return modal with the raw key (only shown once)
	return c.RenderPartial("partials/apikey-modal.html", map[string]interface{}{
		"Key":    result,
		"RawKey": result.RawKey,
	})
}

// RevokeAPIKey revokes an API key.
func (h *Handler) RevokeAPIKey(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	keyID := c.Param("id")
	if keyID == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Key ID is required",
		})
	}

	// Verify ownership and revoke
	keys, err := h.app.Auth.ListAPIKeys(c.Context(), userID)
	if err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to verify key ownership",
		})
	}

	var found bool
	for _, k := range keys {
		if k.ID == keyID {
			found = true
			break
		}
	}

	if !found {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "API key not found",
		})
	}

	if err := h.app.Auth.RevokeAPIKey(c.Context(), keyID); err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to revoke API key",
		})
	}

	// Trigger refresh of key list
	c.HXTrigger("apikey-revoked")
	return c.RenderPartial("partials/flash.html", Flash{
		Type:    "success",
		Message: "API key revoked successfully",
	})
}
