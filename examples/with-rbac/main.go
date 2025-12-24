// Package main demonstrates goauth with RBAC (Role-Based Access Control).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/aloks98/goauth"
	"github.com/aloks98/goauth/middleware"
	"github.com/aloks98/goauth/store/memory"
	"github.com/aloks98/goauth/token"
)

// Claims defines custom JWT claims.
type Claims struct {
	goauth.StandardClaims
}

// authAdapter adapts goauth.Auth to middleware interfaces.
type authAdapter struct {
	auth *goauth.Auth[*Claims]
}

func (a *authAdapter) ValidateAccessToken(ctx context.Context, tokenString string) (interface{}, error) {
	return a.auth.ValidateAccessToken(ctx, tokenString)
}

func (a *authAdapter) ExtractUserID(claims interface{}) string {
	if c, ok := claims.(*token.Claims); ok {
		return c.UserID
	}
	return ""
}

func (a *authAdapter) ExtractPermissions(claims interface{}) []string {
	return nil
}

func (a *authAdapter) HasPermission(ctx context.Context, userID string, permission string) (bool, error) {
	return a.auth.HasPermission(ctx, userID, permission)
}

func (a *authAdapter) HasAllPermissions(ctx context.Context, userID string, permissions []string) (bool, error) {
	return a.auth.HasAllPermissions(ctx, userID, permissions)
}

func (a *authAdapter) HasAnyPermission(ctx context.Context, userID string, permissions []string) (bool, error) {
	return a.auth.HasAnyPermission(ctx, userID, permissions)
}

func main() {
	// Create store
	store := memory.New()
	defer store.Close()

	// Initialize goauth with RBAC
	auth, err := goauth.New[*Claims](
		goauth.WithSecret("your-32-character-secret-key!!!!"),
		goauth.WithStore(store),
		goauth.WithRBACFromFile("./permissions.yaml"), // Enable RBAC
	)
	if err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}
	defer auth.Close()

	// Create adapter
	adapter := &authAdapter{auth: auth}

	// Setup routes
	mux := http.NewServeMux()

	// Auth middleware
	authMW := middleware.Authenticate(adapter, adapter, nil)

	// Public routes
	mux.HandleFunc("POST /login", loginHandler(auth))
	mux.HandleFunc("GET /roles", listRolesHandler(auth))

	// Protected routes
	mux.Handle("GET /me", authMW(http.HandlerFunc(meHandler(auth))))
	mux.Handle("POST /users/{id}/role", authMW(http.HandlerFunc(assignRoleHandler(auth))))
	mux.Handle("GET /users/{id}/permissions", authMW(http.HandlerFunc(getPermissionsHandler(auth))))

	// Permission-protected routes
	mux.Handle("GET /posts", authMW(requirePermission(adapter, "posts:read", http.HandlerFunc(listPostsHandler))))
	mux.Handle("POST /posts", authMW(requirePermission(adapter, "posts:create", http.HandlerFunc(createPostHandler))))
	mux.Handle("DELETE /posts/{id}", authMW(requirePermission(adapter, "posts:delete", http.HandlerFunc(deletePostHandler))))

	// Admin-only route
	mux.Handle("GET /settings", authMW(requirePermission(adapter, "settings:read", http.HandlerFunc(settingsHandler))))

	fmt.Println("Server running on http://localhost:8080")
	fmt.Println("\nAvailable roles (from permissions.yaml):")
	for _, role := range auth.GetAllRoles() {
		fmt.Printf("  - %s: %s\n", role.Key, role.Description)
	}
	fmt.Println("\nTry these endpoints:")
	fmt.Println("  POST /login?role=editor  - Login with a role")
	fmt.Println("  GET  /roles              - List available roles")
	fmt.Println("  GET  /me                 - Get current user info")
	fmt.Println("  GET  /posts              - List posts (requires posts:read)")
	fmt.Println("  POST /posts              - Create post (requires posts:create)")
	fmt.Println("  GET  /settings           - View settings (requires settings:read)")

	log.Fatal(http.ListenAndServe(":8080", mux))
}

func requirePermission(checker middleware.PermissionChecker, permission string, next http.Handler) http.Handler {
	return middleware.RequirePermission(checker, permission, nil)(next)
}

func loginHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get role from query param (in real app, this comes from user DB)
		role := r.URL.Query().Get("role")
		if role == "" {
			role = "viewer" // Default role
		}

		// Create a unique user ID
		userID := "user-" + role

		// Assign role to user (copies permissions from role template)
		ctx := r.Context()
		if err := auth.AssignRole(ctx, userID, role); err != nil {
			http.Error(w, "Invalid role: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Generate tokens
		pair, err := auth.GenerateTokenPair(ctx, userID, map[string]any{"role": role})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"message":       fmt.Sprintf("Logged in as %s with role '%s'", userID, role),
			"access_token":  pair.AccessToken,
			"refresh_token": pair.RefreshToken,
			"expires_in":    pair.ExpiresIn,
		})
	}
}

func listRolesHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roles := auth.GetAllRoles()

		result := make([]map[string]any, len(roles))
		for i, role := range roles {
			result[i] = map[string]any{
				"key":         role.Key,
				"name":        role.Name,
				"description": role.Description,
				"permissions": role.Permissions,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func meHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := middleware.GetUserID(r.Context())

		// Get user permissions
		perms, err := auth.GetUserPermissions(r.Context(), userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"user_id":     userID,
			"role":        perms.RoleLabel,
			"permissions": perms.Permissions,
			"version":     perms.PermissionVersion,
		})
	}
}

func assignRoleHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetUserID := r.PathValue("id")

		var req struct {
			Role string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Check if current user can manage users
		currentUserID := middleware.GetUserID(r.Context())
		canManage, err := auth.HasPermission(r.Context(), currentUserID, "users:update")
		if err != nil || !canManage {
			http.Error(w, "Permission denied", http.StatusForbidden)
			return
		}

		// Assign role
		if err := auth.AssignRole(r.Context(), targetUserID, req.Role); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": fmt.Sprintf("Assigned role '%s' to user '%s'", req.Role, targetUserID),
		})
	}
}

func getPermissionsHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetUserID := r.PathValue("id")

		perms, err := auth.GetUserPermissions(r.Context(), targetUserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(perms)
	}
}

func listPostsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]string{
		{"id": "1", "title": "First Post", "status": "published"},
		{"id": "2", "title": "Draft Post", "status": "draft"},
	})
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Post created successfully",
		"id":      "3",
	})
}

func deletePostHandler(w http.ResponseWriter, r *http.Request) {
	postID := r.PathValue("id")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Post %s deleted", postID),
	})
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	// Only admins can access this
	userID := middleware.GetUserID(r.Context())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"accessed_by": userID,
		"settings": map[string]any{
			"site_name":    "My App",
			"max_users":    1000,
			"debug_mode":   false,
			"maintenance":  false,
		},
	})
}

// extractToken gets the bearer token from Authorization header
func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}
