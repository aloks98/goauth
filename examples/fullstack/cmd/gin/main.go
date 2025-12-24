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

	"github.com/gin-gonic/gin"

	"github.com/aloks98/goauth/examples/fullstack/internal/app"
	"github.com/aloks98/goauth/examples/fullstack/internal/handlers"
	"github.com/aloks98/goauth/examples/fullstack/internal/htmx"
	"github.com/aloks98/goauth/middleware"
	ginmw "github.com/aloks98/goauth/middleware/gin"
)

// ginContext implements handlers.Context for gin.
type ginContext struct {
	c   *gin.Context
	app *app.App
}

func (g *ginContext) Context() context.Context {
	return g.c.Request.Context()
}

func (g *ginContext) Request() *http.Request {
	return g.c.Request
}

func (g *ginContext) ResponseWriter() http.ResponseWriter {
	return g.c.Writer
}

func (g *ginContext) UserID() string {
	return middleware.GetUserID(g.c.Request.Context())
}

func (g *ginContext) Claims() interface{} {
	return middleware.GetClaims(g.c.Request.Context())
}

func (g *ginContext) FormValue(key string) string {
	return g.c.PostForm(key)
}

func (g *ginContext) Param(key string) string {
	return g.c.Param(key)
}

func (g *ginContext) SetCookie(cookie *http.Cookie) {
	http.SetCookie(g.c.Writer, cookie)
}

func (g *ginContext) Redirect(url string, code int) error {
	g.c.Redirect(code, url)
	return nil
}

func (g *ginContext) Render(name string, data interface{}) error {
	var buf bytes.Buffer

	if err := g.app.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}

	g.c.Header("Content-Type", "text/html; charset=utf-8")

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
			return g.app.Templates.ExecuteTemplate(g.c.Writer, "layouts/auth.html", layoutData)
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
		return g.app.Templates.ExecuteTemplate(g.c.Writer, "layouts/base.html", layoutData)
	}

	_, err := g.c.Writer.Write(buf.Bytes())
	return err
}

func (g *ginContext) RenderPartial(name string, data interface{}) error {
	g.c.Header("Content-Type", "text/html; charset=utf-8")
	return g.app.Templates.ExecuteTemplate(g.c.Writer, name, data)
}

func (g *ginContext) JSON(code int, data interface{}) error {
	g.c.JSON(code, data)
	return nil
}

func (g *ginContext) String(code int, s string) error {
	g.c.String(code, s)
	return nil
}

func (g *ginContext) NoContent(code int) error {
	g.c.Status(code)
	return nil
}

func (g *ginContext) IsHTMX() bool {
	return htmx.IsHTMXRequest(g.c.Request)
}

func (g *ginContext) HXRedirect(url string) {
	htmx.Redirect(g.c.Writer, url)
}

func (g *ginContext) HXTrigger(event string) {
	htmx.Trigger(g.c.Writer, event)
}

func wrapHandler(application *app.App, h func(c handlers.Context) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := &ginContext{c: c, app: application}
		if err := h(ctx); err != nil {
			log.Printf("Handler error: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
		}
	}
}

func requireAuth(application *app.App) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Request.Cookie("access_token")
		if err != nil || cookie.Value == "" {
			if htmx.IsHTMXRequest(c.Request) {
				htmx.Redirect(c.Writer, "/login")
				c.AbortWithStatus(http.StatusOK)
				return
			}
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		claims, err := application.Auth.ValidateAccessToken(c.Request.Context(), cookie.Value)
		if err != nil {
			if htmx.IsHTMXRequest(c.Request) {
				htmx.Redirect(c.Writer, "/login")
				c.AbortWithStatus(http.StatusOK)
				return
			}
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		ctx := context.WithValue(c.Request.Context(), "user_id", claims.UserID)
		ctx = middleware.SetClaims(ctx, claims)
		ctx = middleware.SetUserID(ctx, claims.UserID)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func optionalAuth(application *app.App) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Request.Cookie("access_token")
		if err == nil && cookie.Value != "" {
			claims, err := application.Auth.ValidateAccessToken(c.Request.Context(), cookie.Value)
			if err == nil && claims != nil {
				ctx := context.WithValue(c.Request.Context(), "user_id", claims.UserID)
				ctx = middleware.SetClaims(ctx, claims)
				ctx = middleware.SetUserID(ctx, claims.UserID)
				c.Request = c.Request.WithContext(ctx)
			}
		}
		c.Next()
	}
}

func main() {
	log.Println("Starting GoAuth Full-Stack Demo (Gin)")

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

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Static files
	r.Static("/static", cfg.StaticPath)

	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusSeeOther, "/login")
	})

	// Auth routes
	auth := r.Group("/")
	auth.Use(optionalAuth(application))
	{
		auth.GET("/login", wrapHandler(application, h.ShowLogin))
		auth.POST("/login", wrapHandler(application, h.Login))
		auth.GET("/register", wrapHandler(application, h.ShowRegister))
		auth.POST("/register", wrapHandler(application, h.Register))
	}

	// Protected routes
	protected := r.Group("/")
	protected.Use(requireAuth(application))
	{
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
	}

	r.POST("/refresh", wrapHandler(application, h.Refresh))

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		log.Printf("Server listening on http://localhost:%s", cfg.Port)
		log.Println("Demo users: admin@example.com/admin123, user@example.com/user123, viewer@example.com/viewer123")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
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

// Ensure we use the ginmw package to avoid unused import error
var _ = ginmw.Authenticate
