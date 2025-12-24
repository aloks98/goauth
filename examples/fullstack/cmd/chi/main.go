package main

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/aloks98/goauth/examples/fullstack/internal/app"
	"github.com/aloks98/goauth/examples/fullstack/internal/handlers"
	"github.com/aloks98/goauth/examples/fullstack/internal/htmx"
	"github.com/aloks98/goauth/middleware"
)

// chiContext implements handlers.Context for chi.
type chiContext struct {
	w   http.ResponseWriter
	r   *http.Request
	app *app.App
}

func (c *chiContext) Context() context.Context {
	return c.r.Context()
}

func (c *chiContext) Request() *http.Request {
	return c.r
}

func (c *chiContext) ResponseWriter() http.ResponseWriter {
	return c.w
}

func (c *chiContext) UserID() string {
	return middleware.GetUserID(c.r.Context())
}

func (c *chiContext) Claims() interface{} {
	return middleware.GetClaims(c.r.Context())
}

func (c *chiContext) FormValue(key string) string {
	return c.r.FormValue(key)
}

func (c *chiContext) Param(key string) string {
	return chi.URLParam(c.r, key)
}

func (c *chiContext) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.w, cookie)
}

func (c *chiContext) Redirect(url string, code int) error {
	http.Redirect(c.w, c.r, url, code)
	return nil
}

func (c *chiContext) Render(name string, data interface{}) error {
	var buf bytes.Buffer

	if err := c.app.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}

	c.w.Header().Set("Content-Type", "text/html; charset=utf-8")

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
			return c.app.Templates.ExecuteTemplate(c.w, "layouts/auth.html", layoutData)
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
		return c.app.Templates.ExecuteTemplate(c.w, "layouts/base.html", layoutData)
	}

	_, err := c.w.Write(buf.Bytes())
	return err
}

func (c *chiContext) RenderPartial(name string, data interface{}) error {
	c.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return c.app.Templates.ExecuteTemplate(c.w, name, data)
}

func (c *chiContext) JSON(code int, data interface{}) error {
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(code)
	return json.NewEncoder(c.w).Encode(data)
}

func (c *chiContext) String(code int, s string) error {
	c.w.Header().Set("Content-Type", "text/plain")
	c.w.WriteHeader(code)
	_, err := c.w.Write([]byte(s))
	return err
}

func (c *chiContext) NoContent(code int) error {
	c.w.WriteHeader(code)
	return nil
}

func (c *chiContext) IsHTMX() bool {
	return htmx.IsHTMXRequest(c.r)
}

func (c *chiContext) HXRedirect(url string) {
	htmx.Redirect(c.w, url)
}

func (c *chiContext) HXTrigger(event string) {
	htmx.Trigger(c.w, event)
}

func wrapHandler(application *app.App, h func(c handlers.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := &chiContext{w: w, r: r, app: application}
		if err := h(ctx); err != nil {
			log.Printf("Handler error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func requireAuth(application *app.App) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("access_token")
			if err != nil || cookie.Value == "" {
				if htmx.IsHTMXRequest(r) {
					htmx.Redirect(w, "/login")
					w.WriteHeader(http.StatusOK)
					return
				}
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			claims, err := application.Auth.ValidateAccessToken(r.Context(), cookie.Value)
			if err != nil {
				if htmx.IsHTMXRequest(r) {
					htmx.Redirect(w, "/login")
					w.WriteHeader(http.StatusOK)
					return
				}
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			ctx := context.WithValue(r.Context(), app.ContextKeyUserID, claims.UserID)
			ctx = middleware.SetClaims(ctx, claims)
			ctx = middleware.SetUserID(ctx, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func optionalAuth(application *app.App) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("access_token")
			if err == nil && cookie.Value != "" {
				claims, err := application.Auth.ValidateAccessToken(r.Context(), cookie.Value)
				if err == nil && claims != nil {
					ctx := context.WithValue(r.Context(), app.ContextKeyUserID, claims.UserID)
					ctx = middleware.SetClaims(ctx, claims)
					ctx = middleware.SetUserID(ctx, claims.UserID)
					r = r.WithContext(ctx)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	log.Println("Starting GoAuth Full-Stack Demo (Chi)")

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

	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	// Static files
	fs := http.FileServer(http.Dir(cfg.StaticPath))
	r.Handle("/static/*", http.StripPrefix("/static/", fs))

	// Public routes
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	// Auth routes
	r.Group(func(r chi.Router) {
		r.Use(optionalAuth(application))
		r.Get("/login", wrapHandler(application, h.ShowLogin))
		r.Post("/login", wrapHandler(application, h.Login))
		r.Get("/register", wrapHandler(application, h.ShowRegister))
		r.Post("/register", wrapHandler(application, h.Register))
	})

	// Refresh (no auth required)
	r.Post("/refresh", wrapHandler(application, h.Refresh))

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(requireAuth(application))

		r.Post("/logout", wrapHandler(application, h.Logout))
		r.Post("/logout-all", wrapHandler(application, h.LogoutAll))
		r.Get("/dashboard", wrapHandler(application, h.ShowDashboard))

		// API Keys
		r.Get("/api-keys", wrapHandler(application, h.ShowAPIKeys))
		r.Get("/api/keys", wrapHandler(application, h.ListAPIKeys))
		r.Get("/api/keys/new", wrapHandler(application, h.ShowCreateAPIKeyForm))
		r.Post("/api/keys", wrapHandler(application, h.CreateAPIKey))
		r.Delete("/api/keys/{id}", wrapHandler(application, h.RevokeAPIKey))

		// RBAC
		r.Get("/rbac", wrapHandler(application, h.ShowRBAC))
		r.Post("/rbac/assign", wrapHandler(application, h.AssignRole))
		r.Post("/rbac/add-permission", wrapHandler(application, h.AddPermission))
		r.Post("/rbac/check", wrapHandler(application, h.CheckPermission))
		r.Get("/rbac/permissions", wrapHandler(application, h.GetPermissions))

		// Admin
		r.Get("/admin", wrapHandler(application, h.ShowAdmin))
		r.Get("/admin/users", wrapHandler(application, h.ListUsers))
		r.Post("/admin/users/{id}/revoke-tokens", wrapHandler(application, h.RevokeUserTokens))
		r.Post("/admin/users/{id}/assign-role", wrapHandler(application, h.AdminAssignRole))
		r.Get("/admin/cleanup/stats", wrapHandler(application, h.GetCleanupStats))
		r.Post("/admin/cleanup/run", wrapHandler(application, h.RunCleanup))
	})

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
