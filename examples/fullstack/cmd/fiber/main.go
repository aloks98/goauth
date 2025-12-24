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

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/valyala/fasthttp/fasthttpadaptor"

	"github.com/aloks98/goauth/examples/fullstack/internal/app"
	"github.com/aloks98/goauth/examples/fullstack/internal/handlers"
)

// fiberContext implements handlers.Context for fiber.
type fiberContext struct {
	c   *fiber.Ctx
	app *app.App
	r   *http.Request
}

func (f *fiberContext) Context() context.Context {
	return f.c.UserContext()
}

func (f *fiberContext) Request() *http.Request {
	if f.r == nil {
		f.r = &http.Request{}
		fasthttpadaptor.ConvertRequest(f.c.Context(), f.r, true)
	}
	return f.r
}

func (f *fiberContext) ResponseWriter() http.ResponseWriter {
	return nil // Fiber uses its own response handling
}

func (f *fiberContext) UserID() string {
	if userID := f.c.Locals("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

func (f *fiberContext) Claims() interface{} {
	return f.c.Locals("claims")
}

func (f *fiberContext) FormValue(key string) string {
	return f.c.FormValue(key)
}

func (f *fiberContext) Param(key string) string {
	return f.c.Params(key)
}

func (f *fiberContext) SetCookie(cookie *http.Cookie) {
	fc := &fiber.Cookie{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Path:     cookie.Path,
		Domain:   cookie.Domain,
		MaxAge:   cookie.MaxAge,
		Secure:   cookie.Secure,
		HTTPOnly: cookie.HttpOnly,
	}
	if cookie.SameSite == http.SameSiteLaxMode {
		fc.SameSite = "Lax"
	} else if cookie.SameSite == http.SameSiteStrictMode {
		fc.SameSite = "Strict"
	} else if cookie.SameSite == http.SameSiteNoneMode {
		fc.SameSite = "None"
	}
	f.c.Cookie(fc)
}

func (f *fiberContext) Redirect(url string, code int) error {
	return f.c.Redirect(url, code)
}

func (f *fiberContext) Render(name string, data interface{}) error {
	var buf bytes.Buffer

	if err := f.app.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}

	f.c.Set("Content-Type", "text/html; charset=utf-8")

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
			var out bytes.Buffer
			if err := f.app.Templates.ExecuteTemplate(&out, "layouts/auth.html", layoutData); err != nil {
				return err
			}
			return f.c.Send(out.Bytes())
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
		var out bytes.Buffer
		if err := f.app.Templates.ExecuteTemplate(&out, "layouts/base.html", layoutData); err != nil {
			return err
		}
		return f.c.Send(out.Bytes())
	}

	return f.c.Send(buf.Bytes())
}

func (f *fiberContext) RenderPartial(name string, data interface{}) error {
	f.c.Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := f.app.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}
	return f.c.Send(buf.Bytes())
}

func (f *fiberContext) JSON(code int, data interface{}) error {
	return f.c.Status(code).JSON(data)
}

func (f *fiberContext) String(code int, s string) error {
	return f.c.Status(code).SendString(s)
}

func (f *fiberContext) NoContent(code int) error {
	return f.c.SendStatus(code)
}

func (f *fiberContext) IsHTMX() bool {
	return f.c.Get("HX-Request") == "true"
}

func (f *fiberContext) HXRedirect(url string) {
	f.c.Set("HX-Redirect", url)
}

func (f *fiberContext) HXTrigger(event string) {
	f.c.Set("HX-Trigger", event)
}

func wrapHandler(application *app.App, h func(c handlers.Context) error) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := &fiberContext{c: c, app: application}
		if err := h(ctx); err != nil {
			log.Printf("Handler error: %v", err)
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		return nil
	}
}

func requireAuth(application *app.App) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenValue := c.Cookies("access_token")
		if tokenValue == "" {
			if c.Get("HX-Request") == "true" {
				c.Set("HX-Redirect", "/login")
				return c.SendStatus(fiber.StatusOK)
			}
			return c.Redirect("/login", fiber.StatusSeeOther)
		}

		claims, err := application.Auth.ValidateAccessToken(c.UserContext(), tokenValue)
		if err != nil {
			if c.Get("HX-Request") == "true" {
				c.Set("HX-Redirect", "/login")
				return c.SendStatus(fiber.StatusOK)
			}
			return c.Redirect("/login", fiber.StatusSeeOther)
		}

		c.Locals("user_id", claims.UserID)
		c.Locals("claims", claims)
		return c.Next()
	}
}

func optionalAuth(application *app.App) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenValue := c.Cookies("access_token")
		if tokenValue != "" {
			claims, err := application.Auth.ValidateAccessToken(c.UserContext(), tokenValue)
			if err == nil && claims != nil {
				c.Locals("user_id", claims.UserID)
				c.Locals("claims", claims)
			}
		}
		return c.Next()
	}
}

func main() {
	log.Println("Starting GoAuth Full-Stack Demo (Fiber)")

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

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	app.Use(logger.New())
	app.Use(recover.New())

	// Static files
	app.Static("/static", cfg.StaticPath)

	// Public routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Redirect("/login", fiber.StatusSeeOther)
	})

	// Auth routes
	auth := app.Group("")
	auth.Use(optionalAuth(application))
	auth.Get("/login", wrapHandler(application, h.ShowLogin))
	auth.Post("/login", wrapHandler(application, h.Login))
	auth.Get("/register", wrapHandler(application, h.ShowRegister))
	auth.Post("/register", wrapHandler(application, h.Register))

	// Refresh
	app.Post("/refresh", wrapHandler(application, h.Refresh))

	// Protected routes
	protected := app.Group("")
	protected.Use(requireAuth(application))

	protected.Post("/logout", wrapHandler(application, h.Logout))
	protected.Post("/logout-all", wrapHandler(application, h.LogoutAll))
	protected.Get("/dashboard", wrapHandler(application, h.ShowDashboard))

	// API Keys
	protected.Get("/api-keys", wrapHandler(application, h.ShowAPIKeys))
	protected.Get("/api/keys", wrapHandler(application, h.ListAPIKeys))
	protected.Get("/api/keys/new", wrapHandler(application, h.ShowCreateAPIKeyForm))
	protected.Post("/api/keys", wrapHandler(application, h.CreateAPIKey))
	protected.Delete("/api/keys/:id", wrapHandler(application, h.RevokeAPIKey))

	// RBAC
	protected.Get("/rbac", wrapHandler(application, h.ShowRBAC))
	protected.Post("/rbac/assign", wrapHandler(application, h.AssignRole))
	protected.Post("/rbac/add-permission", wrapHandler(application, h.AddPermission))
	protected.Post("/rbac/check", wrapHandler(application, h.CheckPermission))
	protected.Get("/rbac/permissions", wrapHandler(application, h.GetPermissions))

	// Admin
	protected.Get("/admin", wrapHandler(application, h.ShowAdmin))
	protected.Get("/admin/users", wrapHandler(application, h.ListUsers))
	protected.Post("/admin/users/:id/revoke-tokens", wrapHandler(application, h.RevokeUserTokens))
	protected.Post("/admin/users/:id/assign-role", wrapHandler(application, h.AdminAssignRole))
	protected.Get("/admin/cleanup/stats", wrapHandler(application, h.GetCleanupStats))
	protected.Post("/admin/cleanup/run", wrapHandler(application, h.RunCleanup))

	go func() {
		log.Printf("Server listening on http://localhost:%s", cfg.Port)
		log.Println("Demo users: admin@example.com/admin123, user@example.com/user123, viewer@example.com/viewer123")
		if err := app.Listen(":" + cfg.Port); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	if err := app.ShutdownWithTimeout(30 * time.Second); err != nil {
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
