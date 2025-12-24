// Package main demonstrates basic usage of goauth with net/http.
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

// Claims defines custom JWT claims for this application.
type Claims struct {
	goauth.StandardClaims
	Email string `json:"email,omitempty"`
	Role  string `json:"role,omitempty"`
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
	return nil // Simple example without RBAC
}

func main() {
	// Create an in-memory store (use SQL store for production)
	store := memory.New()
	defer store.Close()

	// Initialize goauth
	auth, err := goauth.New[*Claims](
		goauth.WithSecret("your-32-character-secret-key!!!!"), // Use a strong secret in production
		goauth.WithStore(store),
	)
	if err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}
	defer auth.Close()

	// Create adapter for middleware
	adapter := &authAdapter{auth: auth}

	// Setup routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("POST /login", loginHandler(auth))
	mux.HandleFunc("POST /refresh", refreshHandler(auth))

	// Protected routes - using middleware
	authMiddleware := middleware.Authenticate(adapter, adapter, nil)
	mux.Handle("GET /me", authMiddleware(http.HandlerFunc(meHandler)))
	mux.Handle("POST /logout", authMiddleware(logoutHandler(auth)))

	// API key routes
	mux.Handle("POST /api-keys", authMiddleware(createAPIKeyHandler(auth)))
	mux.Handle("GET /api-keys", authMiddleware(listAPIKeysHandler(auth)))

	// Start server
	fmt.Println("Server running on http://localhost:8080")
	fmt.Println("\nTry these endpoints:")
	fmt.Println("  POST /login       - Get access and refresh tokens")
	fmt.Println("  POST /refresh     - Refresh your tokens")
	fmt.Println("  GET  /me          - Get current user (requires auth)")
	fmt.Println("  POST /logout      - Revoke current token")
	fmt.Println("  POST /api-keys    - Create an API key")
	fmt.Println("  GET  /api-keys    - List your API keys")

	log.Fatal(http.ListenAndServe(":8080", mux))
}

func loginHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In a real app, you would validate credentials here
		userID := "user-123"
		customClaims := map[string]any{
			"email": "user@example.com",
			"role":  "admin",
		}

		pair, err := auth.GenerateTokenPair(r.Context(), userID, customClaims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pair)
	}
}

func refreshHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		pair, err := auth.RefreshTokens(r.Context(), req.RefreshToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pair)
	}
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	claims := middleware.GetClaims(r.Context())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": userID,
		"claims":  claims,
	})
}

func logoutHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		if err := auth.RevokeAccessToken(r.Context(), tokenStr); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func createAPIKeyHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := middleware.GetUserID(r.Context())
		if userID == "" {
			http.Error(w, "No user ID found", http.StatusUnauthorized)
			return
		}

		result, err := auth.CreateAPIKey(r.Context(), userID, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":      result.ID,
			"raw_key": result.RawKey,
			"hint":    result.Hint,
			"message": "Save this key! It won't be shown again.",
		})
	}
}

func listAPIKeysHandler(auth *goauth.Auth[*Claims]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := middleware.GetUserID(r.Context())
		if userID == "" {
			http.Error(w, "No user ID found", http.StatusUnauthorized)
			return
		}

		keys, err := auth.ListAPIKeys(r.Context(), userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)
	}
}
