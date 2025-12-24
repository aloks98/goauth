package main

import (
	"bytes"
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"

	"github.com/aloks98/goauth/examples/fullstack/internal/app"
	"github.com/aloks98/goauth/examples/fullstack/internal/handlers"
	"github.com/aloks98/goauth/examples/fullstack/internal/htmx"
	"github.com/aloks98/goauth/middleware"
)

// echoContext implements handlers.Context for echo.
type echoContext struct {
	c   echo.Context
	app *app.App
}

func (e *echoContext) Context() context.Context {
	return e.c.Request().Context()
}

func (e *echoContext) Request() *http.Request {
	return e.c.Request()
}

func (e *echoContext) ResponseWriter() http.ResponseWriter {
	return e.c.Response().Writer
}

func (e *echoContext) UserID() string {
	return middleware.GetUserID(e.c.Request().Context())
}

func (e *echoContext) Claims() interface{} {
	return middleware.GetClaims(e.c.Request().Context())
}

func (e *echoContext) FormValue(key string) string {
	return e.c.FormValue(key)
}

func (e *echoContext) Param(key string) string {
	return e.c.Param(key)
}

func (e *echoContext) SetCookie(cookie *http.Cookie) {
	e.c.SetCookie(cookie)
}

func (e *echoContext) Redirect(url string, code int) error {
	return e.c.Redirect(code, url)
}

func (e *echoContext) Render(name string, data interface{}) error {
	var buf bytes.Buffer

	if err := e.app.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}

	e.c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")

	if strings.HasPrefix(name, "pages/") {
		// Auth pages use auth layout
		if name == "pages/login.html" || name == "pages/register.html" {
			layoutData := map[string]interface{}{
				"Content": template.HTML(buf.String()),
				"Title":   "",
			}
			if pd, ok := data.(handlers.PageData); ok {
				layoutData["Title"] = pd.Title
			}
			return e.app.Templates.ExecuteTemplate(e.c.Response().Writer, "layouts/auth.html", layoutData)
		}

		// Other pages use base layout
		layoutData := map[string]interface{}{
			"Content": template.HTML(buf.String()),
			"Title":   "",
			"Active":  "",
			"User":    nil,
		}
		if pd, ok := data.(handlers.PageData); ok {
			layoutData["Title"] = pd.Title
			layoutData["Active"] = pd.Active
			layoutData["User"] = pd.User
		} else if m, ok := data.(map[string]interface{}); ok {
			if v, ok := m["Title"]; ok {
				layoutData["Title"] = v
			}
			if v, ok := m["Active"]; ok {
				layoutData["Active"] = v
			}
			if v, ok := m["User"]; ok {
				layoutData["User"] = v
			}
		}
		return e.app.Templates.ExecuteTemplate(e.c.Response().Writer, "layouts/base.html", layoutData)
	}

	_, err := e.c.Response().Writer.Write(buf.Bytes())
	return err
}

func (e *echoContext) RenderPartial(name string, data interface{}) error {
	e.c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return e.app.Templates.ExecuteTemplate(e.c.Response().Writer, name, data)
}

func (e *echoContext) JSON(code int, data interface{}) error {
	return e.c.JSON(code, data)
}

func (e *echoContext) String(code int, s string) error {
	return e.c.String(code, s)
}

func (e *echoContext) NoContent(code int) error {
	return e.c.NoContent(code)
}

func (e *echoContext) IsHTMX() bool {
	return htmx.IsHTMXRequest(e.c.Request())
}

func (e *echoContext) HXRedirect(url string) {
	htmx.Redirect(e.c.Response().Writer, url)
}

func (e *echoContext) HXTrigger(event string) {
	htmx.Trigger(e.c.Response().Writer, event)
}

func wrapHandler(application *app.App, h func(c handlers.Context) error) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := &echoContext{c: c, app: application}
		if err := h(ctx); err != nil {
			log.Printf("Handler error: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError)
		}
		return nil
	}
}

func requireAuth(application *app.App) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("access_token")
			if err != nil || cookie.Value == "" {
				if htmx.IsHTMXRequest(c.Request()) {
					htmx.Redirect(c.Response().Writer, "/login")
					return c.NoContent(http.StatusOK)
				}
				return c.Redirect(http.StatusSeeOther, "/login")
			}

			claims, err := application.Auth.ValidateAccessToken(c.Request().Context(), cookie.Value)
			if err != nil {
				if htmx.IsHTMXRequest(c.Request()) {
					htmx.Redirect(c.Response().Writer, "/login")
					return c.NoContent(http.StatusOK)
				}
				return c.Redirect(http.StatusSeeOther, "/login")
			}

			ctx := context.WithValue(c.Request().Context(), app.ContextKeyUserID, claims.UserID)
			ctx = middleware.SetClaims(ctx, claims)
			ctx = middleware.SetUserID(ctx, claims.UserID)
			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}

func optionalAuth(application *app.App) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("access_token")
			if err == nil && cookie.Value != "" {
				claims, err := application.Auth.ValidateAccessToken(c.Request().Context(), cookie.Value)
				if err == nil && claims != nil {
					ctx := context.WithValue(c.Request().Context(), app.ContextKeyUserID, claims.UserID)
					ctx = middleware.SetClaims(ctx, claims)
					ctx = middleware.SetUserID(ctx, claims.UserID)
					c.SetRequest(c.Request().WithContext(ctx))
				}
			}
			return next(c)
		}
	}
}

func main() {
	log.Println("Starting GoAuth Full-Stack Demo (Echo)")

	cfg := app.DefaultConfig()
	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}
	defer application.Close()

	if err := assignDemoRoles(application); err != nil {
		log.Printf("Warning: Failed to assign demo roles: %v", err)
	}

	h := handlers.New(application)

	e := echo.New()
	e.HideBanner = true
	e.Use(echomw.Logger())
	e.Use(echomw.Recover())

	// Static files
	e.Static("/static", cfg.StaticPath)

	// Public routes
	e.GET("/", func(c echo.Context) error {
		return c.Redirect(http.StatusSeeOther, "/login")
	})

	// Auth routes
	auth := e.Group("")
	auth.Use(optionalAuth(application))
	auth.GET("/login", wrapHandler(application, h.ShowLogin))
	auth.POST("/login", wrapHandler(application, h.Login))
	auth.GET("/register", wrapHandler(application, h.ShowRegister))
	auth.POST("/register", wrapHandler(application, h.Register))

	// Refresh
	e.POST("/refresh", wrapHandler(application, h.Refresh))

	// Protected routes
	protected := e.Group("")
	protected.Use(requireAuth(application))

	protected.POST("/logout", wrapHandler(application, h.Logout))
	protected.POST("/logout-all", wrapHandler(application, h.LogoutAll))
	protected.GET("/dashboard", wrapHandler(application, h.ShowDashboard))

	// API Keys
	protected.GET("/api-keys", wrapHandler(application, h.ShowAPIKeys))
	protected.GET("/api/keys", wrapHandler(application, h.ListAPIKeys))
	protected.GET("/api/keys/new", wrapHandler(application, h.ShowCreateAPIKeyForm))
	protected.POST("/api/keys", wrapHandler(application, h.CreateAPIKey))
	protected.DELETE("/api/keys/:id", wrapHandler(application, h.RevokeAPIKey))

	// RBAC
	protected.GET("/rbac", wrapHandler(application, h.ShowRBAC))
	protected.POST("/rbac/assign", wrapHandler(application, h.AssignRole))
	protected.POST("/rbac/add-permission", wrapHandler(application, h.AddPermission))
	protected.POST("/rbac/check", wrapHandler(application, h.CheckPermission))
	protected.GET("/rbac/permissions", wrapHandler(application, h.GetPermissions))

	// Admin
	protected.GET("/admin", wrapHandler(application, h.ShowAdmin))
	protected.GET("/admin/users", wrapHandler(application, h.ListUsers))
	protected.POST("/admin/users/:id/revoke-tokens", wrapHandler(application, h.RevokeUserTokens))
	protected.POST("/admin/users/:id/assign-role", wrapHandler(application, h.AdminAssignRole))
	protected.GET("/admin/cleanup/stats", wrapHandler(application, h.GetCleanupStats))
	protected.POST("/admin/cleanup/run", wrapHandler(application, h.RunCleanup))

	go func() {
		log.Printf("Server listening on http://localhost:%s", cfg.Port)
		log.Println("Demo users: admin@example.com/admin123, user@example.com/user123, viewer@example.com/viewer123")
		if err := e.Start(":" + cfg.Port); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited properly")
}

func assignDemoRoles(application *app.App) error {
	ctx := context.Background()
	users, _ := application.Users.List(ctx)
	for _, u := range users {
		var role string
		switch u.Email {
		case "admin@example.com":
			role = "admin"
		case "user@example.com":
			role = "user"
		case "viewer@example.com":
			role = "viewer"
		default:
			continue
		}
		if err := application.Auth.AssignRole(ctx, u.ID, role); err != nil {
			log.Printf("Failed to assign role %s to %s: %v", role, u.Email, err)
		} else {
			log.Printf("Assigned role '%s' to %s", role, u.Email)
		}
	}
	return nil
}
