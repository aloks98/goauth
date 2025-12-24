package app

import (
	"os"
	"time"
)

// Config holds application configuration.
type Config struct {
	// Server settings
	Port string

	// Database settings
	DatabaseDSN string

	// Auth settings
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// Paths
	TemplatesPath   string
	StaticPath      string
	PermissionsPath string
}

// DefaultConfig returns configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Port:            getEnv("PORT", "8080"),
		DatabaseDSN:     getEnv("DATABASE_URL", "postgres://goauth:goauth@localhost:15432/goauth_test?sslmode=disable"),
		JWTSecret:       getEnv("JWT_SECRET", "super-secret-key-change-in-production-min-32-chars"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		TemplatesPath:   getEnv("TEMPLATES_PATH", "./templates"),
		StaticPath:      getEnv("STATIC_PATH", "./static"),
		PermissionsPath: getEnv("PERMISSIONS_PATH", "./permissions.yaml"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
