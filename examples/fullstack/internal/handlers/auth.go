package handlers

import (
	"net/http"
	"time"

	"github.com/aloks98/goauth/examples/fullstack/internal/users"
)

// ShowLogin renders the login page.
func (h *Handler) ShowLogin(c Context) error {
	return c.Render("pages/login.html", PageData{
		Title: "Login",
	})
}

// Login handles login form submission.
func (h *Handler) Login(c Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	// Authenticate user
	user, err := h.app.Users.Authenticate(c.Context(), email, password)
	if err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Invalid email or password",
		})
	}

	// Get or create user permissions (assigns default role on first login)
	perms, err := h.app.Auth.GetUserPermissions(c.Context(), user.ID)
	if err != nil {
		// Assign default "user" role for new users
		if err := h.app.Auth.AssignRole(c.Context(), user.ID, "user"); err != nil {
			return c.RenderPartial("partials/flash.html", Flash{
				Type:    "danger",
				Message: "Failed to setup user permissions",
			})
		}
	}
	_ = perms

	// Generate tokens with custom claims
	customClaims := map[string]any{
		"email": user.Email,
		"name":  user.Name,
	}

	tokens, err := h.app.Auth.GenerateTokenPair(c.Context(), user.ID, customClaims)
	if err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to generate tokens",
		})
	}

	// Set cookies
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(15 * time.Minute / time.Second),
	})

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(7 * 24 * time.Hour / time.Second),
	})

	// Redirect to dashboard
	if c.IsHTMX() {
		c.HXRedirect("/dashboard")
		return c.NoContent(http.StatusOK)
	}
	return c.Redirect("/dashboard", http.StatusSeeOther)
}

// ShowRegister renders the registration page.
func (h *Handler) ShowRegister(c Context) error {
	return c.Render("pages/register.html", PageData{
		Title: "Register",
	})
}

// Register handles registration form submission.
func (h *Handler) Register(c Context) error {
	name := c.FormValue("name")
	email := c.FormValue("email")
	password := c.FormValue("password")
	passwordConfirm := c.FormValue("password_confirm")

	// Validate
	if name == "" || email == "" || password == "" {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "All fields are required",
		})
	}

	if len(password) < 6 {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Password must be at least 6 characters",
		})
	}

	if password != passwordConfirm {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Passwords do not match",
		})
	}

	// Create user
	_, err := h.app.Users.Create(c.Context(), email, password, name)
	if err == users.ErrUserExists {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Email already registered",
		})
	}
	if err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to create account",
		})
	}

	// Redirect to login with success message
	if c.IsHTMX() {
		c.HXRedirect("/login")
		return c.NoContent(http.StatusOK)
	}
	return c.Redirect("/login", http.StatusSeeOther)
}

// Logout handles logout.
func (h *Handler) Logout(c Context) error {
	// Get access token from cookie
	if cookie, err := c.Request().Cookie("access_token"); err == nil {
		// Revoke access token
		_ = h.app.Auth.RevokeAccessToken(c.Context(), cookie.Value)
	}

	// Clear cookies
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	if c.IsHTMX() {
		c.HXRedirect("/login")
		return c.NoContent(http.StatusOK)
	}
	return c.Redirect("/login", http.StatusSeeOther)
}

// LogoutAll revokes all user sessions.
func (h *Handler) LogoutAll(c Context) error {
	userID := c.UserID()
	if userID == "" {
		return c.Redirect("/login", http.StatusSeeOther)
	}

	// Revoke all tokens for this user
	if err := h.app.Auth.RevokeAllUserTokens(c.Context(), userID); err != nil {
		return c.RenderPartial("partials/flash.html", Flash{
			Type:    "danger",
			Message: "Failed to revoke sessions",
		})
	}

	// Clear cookies
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	if c.IsHTMX() {
		c.HXRedirect("/login")
		return c.NoContent(http.StatusOK)
	}
	return c.Redirect("/login", http.StatusSeeOther)
}

// Refresh refreshes the access token using the refresh token.
func (h *Handler) Refresh(c Context) error {
	cookie, err := c.Request().Cookie("refresh_token")
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "No refresh token",
		})
	}

	tokens, err := h.app.Auth.RefreshTokens(c.Context(), cookie.Value)
	if err != nil {
		// Clear cookies on refresh failure
		c.SetCookie(&http.Cookie{
			Name:   "access_token",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		c.SetCookie(&http.Cookie{
			Name:   "refresh_token",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Invalid refresh token",
		})
	}

	// Set new cookies
	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(15 * time.Minute / time.Second),
	})

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(7 * 24 * time.Hour / time.Second),
	})

	return c.JSON(http.StatusOK, map[string]string{
		"status": "refreshed",
	})
}
