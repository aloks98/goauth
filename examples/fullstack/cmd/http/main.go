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

	"github.com/aloks98/goauth/examples/fullstack/internal/app"
	"github.com/aloks98/goauth/examples/fullstack/internal/handlers"
	"github.com/aloks98/goauth/examples/fullstack/internal/htmx"
	"github.com/aloks98/goauth/middleware"
)

// httpContext implements handlers.Context for net/http.
type httpContext struct {
	w      http.ResponseWriter
	r      *http.Request
	app    *app.App
	userID string
	claims interface{}
	params map[string]string
}

// Context returns the request context.
func (c *httpContext) Context() context.Context {
	return c.r.Context()
}

// Request returns the HTTP request.
func (c *httpContext) Request() *http.Request {
	return c.r
}

// ResponseWriter returns the HTTP response writer.
func (c *httpContext) ResponseWriter() http.ResponseWriter {
	return c.w
}

// UserID returns the authenticated user ID.
func (c *httpContext) UserID() string {
	return c.userID
}

// Claims returns the JWT claims.
func (c *httpContext) Claims() interface{} {
	return c.claims
}

// FormValue returns a form value.
func (c *httpContext) FormValue(key string) string {
	return c.r.FormValue(key)
}

// Param returns a URL parameter.
func (c *httpContext) Param(key string) string {
	return c.params[key]
}

// SetCookie sets a cookie.
func (c *httpContext) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.w, cookie)
}

// Redirect redirects to a URL.
func (c *httpContext) Redirect(url string, code int) error {
	http.Redirect(c.w, c.r, url, code)
	return nil
}

// Render renders a full page template.
func (c *httpContext) Render(name string, data interface{}) error {
	var buf bytes.Buffer

	// Render content to buffer
	if err := c.app.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("Error rendering content %s: %v", name, err)
		return err
	}

	c.w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Determine which layout to use based on the page
	if strings.HasPrefix(name, "pages/") {
		// Auth pages (login, register) use auth layout
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

	// For other templates (layouts, partials), render directly
	_, err := c.w.Write(buf.Bytes())
	return err
}

// RenderPartial renders a partial template (HTMX response).
func (c *httpContext) RenderPartial(name string, data interface{}) error {
	c.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return c.app.Templates.ExecuteTemplate(c.w, name, data)
}

// JSON sends a JSON response.
func (c *httpContext) JSON(code int, data interface{}) error {
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(code)
	return json.NewEncoder(c.w).Encode(data)
}

// String sends a string response.
func (c *httpContext) String(code int, s string) error {
	c.w.Header().Set("Content-Type", "text/plain")
	c.w.WriteHeader(code)
	_, err := c.w.Write([]byte(s))
	return err
}

// NoContent sends a no content response.
func (c *httpContext) NoContent(code int) error {
	c.w.WriteHeader(code)
	return nil
}

// IsHTMX checks if this is an HTMX request.
func (c *httpContext) IsHTMX() bool {
	return htmx.IsHTMXRequest(c.r)
}

// HXRedirect sends an HTMX redirect header.
func (c *httpContext) HXRedirect(url string) {
	htmx.Redirect(c.w, url)
}

// HXTrigger sends an HTMX trigger event.
func (c *httpContext) HXTrigger(event string) {
	htmx.Trigger(c.w, event)
}

// wrapHandler wraps a handlers.Handler method for net/http.
func wrapHandler(application *app.App, h func(c handlers.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := &httpContext{
			w:      w,
			r:      r,
			app:    application,
			params: make(map[string]string),
		}

		// Extract user ID from context (set by middleware)
		if userID, ok := r.Context().Value("user_id").(string); ok {
			ctx.userID = userID
		}

		// Extract claims from context
		if claims := middleware.GetClaims(r.Context()); claims != nil {
			ctx.claims = claims
		}

		if err := h(ctx); err != nil {
			log.Printf("Handler error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

// wrapHandlerWithParam wraps a handler that needs URL parameters.
func wrapHandlerWithParam(application *app.App, h func(c handlers.Context) error, paramName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := &httpContext{
			w:      w,
			r:      r,
			app:    application,
			params: make(map[string]string),
		}

		// Extract user ID from context
		if userID, ok := r.Context().Value("user_id").(string); ok {
			ctx.userID = userID
		}

		// Extract claims from context
		if claims := middleware.GetClaims(r.Context()); claims != nil {
			ctx.claims = claims
		}

		// Extract param from URL path
		// For paths like /api/keys/{id}/revoke, extract the ID
		parts := strings.Split(r.URL.Path, "/")
		for i, part := range parts {
			if part == "keys" || part == "users" {
				if i+1 < len(parts) {
					ctx.params[paramName] = parts[i+1]
				}
			}
		}

		if err := h(ctx); err != nil {
			log.Printf("Handler error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

// optionalAuthMiddleware extracts user if present but doesn't require auth.
func optionalAuthMiddleware(application *app.App, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to extract token from cookie
		cookie, err := r.Cookie("access_token")
		if err == nil && cookie.Value != "" {
			// Validate token
			claims, err := application.Auth.ValidateAccessToken(r.Context(), cookie.Value)
			if err == nil && claims != nil {
				// Add to context
				ctx := context.WithValue(r.Context(), "user_id", claims.Subject)
				ctx = middleware.SetClaims(ctx, claims)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuthMiddleware requires authentication.
func requireAuthMiddleware(application *app.App, next http.Handler) http.Handler {
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

		// Validate token
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

		// Add to context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = middleware.SetClaims(ctx, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {
	log.Println("Starting GoAuth Full-Stack Demo (net/http)")

	// Load configuration
	cfg := app.DefaultConfig()

	// Create application
	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}
	defer application.Close()

	// Assign demo roles on first startup
	if err := assignDemoRoles(application); err != nil {
		log.Printf("Warning: Failed to assign demo roles: %v", err)
	}

	// Create handlers
	h := handlers.New(application)

	// Create router
	mux := http.NewServeMux()

	// Static files
	fs := http.FileServer(http.Dir(cfg.StaticPath))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Public routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	// Auth routes (no auth required)
	mux.Handle("GET /login", optionalAuthMiddleware(application, wrapHandler(application, h.ShowLogin)))
	mux.Handle("POST /login", optionalAuthMiddleware(application, wrapHandler(application, h.Login)))
	mux.Handle("GET /register", optionalAuthMiddleware(application, wrapHandler(application, h.ShowRegister)))
	mux.Handle("POST /register", optionalAuthMiddleware(application, wrapHandler(application, h.Register)))

	// Auth required routes
	mux.Handle("POST /logout", requireAuthMiddleware(application, wrapHandler(application, h.Logout)))
	mux.Handle("POST /logout-all", requireAuthMiddleware(application, wrapHandler(application, h.LogoutAll)))
	mux.Handle("POST /refresh", wrapHandler(application, h.Refresh))

	// Dashboard
	mux.Handle("GET /dashboard", requireAuthMiddleware(application, wrapHandler(application, h.ShowDashboard)))

	// API Keys
	mux.Handle("GET /api-keys", requireAuthMiddleware(application, wrapHandler(application, h.ShowAPIKeys)))
	mux.Handle("GET /api/keys", requireAuthMiddleware(application, wrapHandler(application, h.ListAPIKeys)))
	mux.Handle("GET /api/keys/new", requireAuthMiddleware(application, wrapHandler(application, h.ShowCreateAPIKeyForm)))
	mux.Handle("POST /api/keys", requireAuthMiddleware(application, wrapHandler(application, h.CreateAPIKey)))
	mux.Handle("DELETE /api/keys/{id}", requireAuthMiddleware(application, wrapHandlerWithParam(application, h.RevokeAPIKey, "id")))

	// RBAC Demo
	mux.Handle("GET /rbac", requireAuthMiddleware(application, wrapHandler(application, h.ShowRBAC)))
	mux.Handle("POST /rbac/assign", requireAuthMiddleware(application, wrapHandler(application, h.AssignRole)))
	mux.Handle("POST /rbac/add-permission", requireAuthMiddleware(application, wrapHandler(application, h.AddPermission)))
	mux.Handle("POST /rbac/check", requireAuthMiddleware(application, wrapHandler(application, h.CheckPermission)))
	mux.Handle("GET /rbac/permissions", requireAuthMiddleware(application, wrapHandler(application, h.GetPermissions)))

	// Admin
	mux.Handle("GET /admin", requireAuthMiddleware(application, wrapHandler(application, h.ShowAdmin)))
	mux.Handle("GET /admin/users", requireAuthMiddleware(application, wrapHandler(application, h.ListUsers)))
	mux.Handle("POST /admin/users/{id}/revoke-tokens", requireAuthMiddleware(application, wrapHandlerWithParam(application, h.RevokeUserTokens, "id")))
	mux.Handle("POST /admin/users/{id}/assign-role", requireAuthMiddleware(application, wrapHandlerWithParam(application, h.AdminAssignRole, "id")))
	mux.Handle("GET /admin/cleanup/stats", requireAuthMiddleware(application, wrapHandler(application, h.GetCleanupStats)))
	mux.Handle("POST /admin/cleanup/run", requireAuthMiddleware(application, wrapHandler(application, h.RunCleanup)))

	// Create server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server listening on http://localhost:%s", cfg.Port)
		log.Println("Demo users: admin@example.com/admin123, user@example.com/user123, viewer@example.com/viewer123")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited properly")
}

// assignDemoRoles assigns roles to demo users.
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
