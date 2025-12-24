package app

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/aloks98/goauth"
	"github.com/aloks98/goauth/examples/fullstack/internal/users"
	"github.com/aloks98/goauth/store/sql"

	// Import pgx driver for PostgreSQL
	_ "github.com/jackc/pgx/v5/stdlib"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// Context keys used in the application.
const (
	// ContextKeyUserID is the context key for the user ID.
	ContextKeyUserID contextKey = "user_id"
)

// App is the main application container.
type App struct {
	Auth      *goauth.Auth[*Claims]
	Users     *users.Store
	Config    *Config
	Templates *template.Template
	Adapter   *AuthAdapter
}

// New creates a new App instance.
func New(cfg *Config) (*App, error) {
	// Create SQL store for PostgreSQL
	store, err := sql.New(&sql.Config{
		Dialect:      sql.PostgreSQL,
		DSN:          cfg.DatabaseDSN,
		TablePrefix:  "demo_",
		MaxOpenConns: 10,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	// Run migrations
	if err := store.Migrate(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create goauth instance with RBAC
	auth, err := goauth.New[*Claims](
		goauth.WithSecret(cfg.JWTSecret),
		goauth.WithStore(store),
		goauth.WithAccessTokenTTL(cfg.AccessTokenTTL),
		goauth.WithRefreshTokenTTL(cfg.RefreshTokenTTL),
		goauth.WithRBACFromFile(cfg.PermissionsPath),
		goauth.WithRoleSyncOnStartup(true),
		goauth.WithPermissionVersionCheck(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth: %w", err)
	}

	// Load templates
	templates, err := loadTemplates(cfg.TemplatesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Create user store and seed demo users
	userStore := users.NewStore()
	if err := seedDemoUsers(userStore); err != nil {
		return nil, fmt.Errorf("failed to seed users: %w", err)
	}

	app := &App{
		Auth:      auth,
		Users:     userStore,
		Config:    cfg,
		Templates: templates,
	}
	app.Adapter = NewAuthAdapter(auth)

	log.Println("Application initialized successfully")
	return app, nil
}

// Close shuts down the application.
func (a *App) Close() error {
	return a.Auth.Close()
}

// GetCleanupStats returns cleanup worker statistics.
func (a *App) GetCleanupStats() map[string]interface{} {
	// For now, return placeholder stats
	// In a real app, you'd track these in the cleanup worker
	return map[string]interface{}{
		"enabled":        true,
		"last_run":       "N/A",
		"next_run":       "N/A",
		"tokens_cleaned": 0,
		"keys_cleaned":   0,
	}
}

// RunCleanup runs manual cleanup of expired tokens and keys.
func (a *App) RunCleanup(ctx context.Context) error {
	store := a.Auth.Store()

	// Clean up expired refresh tokens
	if _, err := store.DeleteExpiredRefreshTokens(ctx); err != nil {
		return err
	}

	// Clean up expired blacklist entries
	if _, err := store.DeleteExpiredBlacklistEntries(ctx); err != nil {
		return err
	}

	// Clean up expired API keys
	if _, err := store.DeleteExpiredAPIKeys(ctx); err != nil {
		return err
	}

	return nil
}

// loadTemplates loads all HTML templates from the templates directory.
func loadTemplates(root string) (*template.Template, error) {
	tmpl := template.New("")

	// Define template functions
	tmpl.Funcs(template.FuncMap{
		"contains": func(slice []string, item string) bool {
			for _, s := range slice {
				if s == item {
					return true
				}
			}
			return false
		},
	})

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".html" {
			return nil
		}

		// Read and parse template
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Use relative path as template name
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		_, err = tmpl.New(name).Parse(string(content))
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", name, err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return tmpl, nil
}

// seedDemoUsers creates demo users for testing.
func seedDemoUsers(store *users.Store) error {
	demoUsers := []struct {
		email    string
		password string
		name     string
	}{
		{"admin@example.com", "admin123", "Admin User"},
		{"user@example.com", "user123", "Regular User"},
		{"viewer@example.com", "viewer123", "Viewer User"},
	}

	for _, u := range demoUsers {
		_, err := store.Create(context.Background(), u.email, u.password, u.name)
		if err != nil {
			// Ignore if already exists
			log.Printf("User %s: %v", u.email, err)
		}
	}

	return nil
}
