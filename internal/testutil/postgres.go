// Package testutil provides testing utilities for goauth.
package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	// PostgreSQL driver
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/aloks98/goauth/store"
	sqlstore "github.com/aloks98/goauth/store/sql"
)

// PostgresContainer wraps a PostgreSQL testcontainer.
type PostgresContainer struct {
	*postgres.PostgresContainer
	DSN string
}

// SetupPostgres creates a PostgreSQL testcontainer and returns a connected store.
// The container is automatically cleaned up when the test finishes.
func SetupPostgres(t testing.TB) store.Store {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("goauth_test"),
		postgres.WithUsername("goauth"),
		postgres.WithPassword("goauth"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate PostgreSQL container: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to get connection string: %v", err)
	}

	s, err := sqlstore.New(&sqlstore.Config{
		Dialect:     sqlstore.PostgreSQL,
		DSN:         dsn,
		TablePrefix: "test_",
	})
	if err != nil {
		t.Fatalf("Failed to create SQL store: %v", err)
	}

	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Logf("Failed to close store: %v", err)
		}
	})

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return s
}

// SetupPostgresWithConfig creates a PostgreSQL testcontainer and returns a connected store
// using the provided table prefix.
func SetupPostgresWithConfig(t testing.TB, tablePrefix string) store.Store {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("goauth_test"),
		postgres.WithUsername("goauth"),
		postgres.WithPassword("goauth"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate PostgreSQL container: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to get connection string: %v", err)
	}

	s, err := sqlstore.New(&sqlstore.Config{
		Dialect:     sqlstore.PostgreSQL,
		DSN:         dsn,
		TablePrefix: tablePrefix,
	})
	if err != nil {
		t.Fatalf("Failed to create SQL store: %v", err)
	}

	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Logf("Failed to close store: %v", err)
		}
	})

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return s
}
