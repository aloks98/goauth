package sql

import (
	"context"
	"testing"
)

func TestNew(t *testing.T) {
	// Note: sql.Open doesn't validate DSN until first connection attempt
	// With empty DSN, New() succeeds but Ping() will fail
	cfg := &Config{
		Dialect: PostgreSQL,
		DSN:     "", // Empty DSN
	}

	s, err := New(cfg)
	if err != nil {
		// Some drivers may error on empty DSN at Open time
		return
	}
	defer s.Close()

	// The real validation happens on Ping
	err = s.Ping(context.Background())
	if err == nil {
		t.Error("expected error when pinging with empty DSN")
	}
}

func TestGetDriverName(t *testing.T) {
	tests := []struct {
		dialect  Dialect
		expected string
	}{
		{PostgreSQL, "pgx"},
		{MySQL, "mysql"},
		{Dialect("unknown"), "pgx"}, // defaults to pgx (postgres via pgx driver)
	}

	for _, tt := range tests {
		got := getDriverName(tt.dialect)
		if got != tt.expected {
			t.Errorf("getDriverName(%v) = %q, want %q", tt.dialect, got, tt.expected)
		}
	}
}

func TestGetDialectQueries(t *testing.T) {
	// Test that queries are returned for each dialect
	pgQueries := getDialectQueries(PostgreSQL, "goauth_")
	if pgQueries == nil {
		t.Fatal("getDialectQueries(PostgreSQL) returned nil")
	}
	if pgQueries.placeholder(1) != "$1" {
		t.Errorf("PostgreSQL placeholder(1) = %q, want $1", pgQueries.placeholder(1))
	}

	mysqlQueries := getDialectQueries(MySQL, "goauth_")
	if mysqlQueries == nil {
		t.Fatal("getDialectQueries(MySQL) returned nil")
	}
	if mysqlQueries.placeholder(1) != "?" {
		t.Errorf("MySQL placeholder(1) = %q, want ?", mysqlQueries.placeholder(1))
	}

	// Unknown dialect defaults to PostgreSQL
	unknownQueries := getDialectQueries(Dialect("unknown"), "goauth_")
	if unknownQueries == nil {
		t.Fatal("getDialectQueries(unknown) returned nil")
	}
	if unknownQueries.placeholder(1) != "$1" {
		t.Errorf("unknown dialect placeholder(1) = %q, want $1", unknownQueries.placeholder(1))
	}
}

func TestGetDialectQueries_CustomPrefix(t *testing.T) {
	// Test that custom table prefix is applied
	queries := getDialectQueries(PostgreSQL, "myapp_")
	if queries == nil {
		t.Fatal("getDialectQueries with custom prefix returned nil")
	}

	// Schema should have custom prefix
	if !contains(queries.schema, "myapp_refresh_tokens") {
		t.Error("schema should contain myapp_refresh_tokens")
	}
	if contains(queries.schema, "goauth_refresh_tokens") {
		t.Error("schema should not contain goauth_refresh_tokens with custom prefix")
	}

	// Queries should have custom prefix
	if !contains(queries.insertRefreshToken, "myapp_refresh_tokens") {
		t.Error("insertRefreshToken should contain myapp_refresh_tokens")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{123, "123"},
		{999999, "999999"},
	}

	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.expected {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNullString(t *testing.T) {
	// Empty string should return invalid NullString
	ns := nullString("")
	if ns.Valid {
		t.Error("nullString(\"\") should be invalid")
	}

	// Non-empty string should return valid NullString
	ns = nullString("test")
	if !ns.Valid {
		t.Error("nullString(\"test\") should be valid")
	}
	if ns.String != "test" {
		t.Errorf("nullString(\"test\").String = %q, want \"test\"", ns.String)
	}
}

func TestDialectConstants(t *testing.T) {
	if PostgreSQL != "postgres" {
		t.Errorf("PostgreSQL = %q, want \"postgres\"", PostgreSQL)
	}
	if MySQL != "mysql" {
		t.Errorf("MySQL = %q, want \"mysql\"", MySQL)
	}
}

func TestQueriesAreLoaded(t *testing.T) {
	// Test that all required queries are loaded for each dialect
	for _, dialect := range []Dialect{PostgreSQL, MySQL} {
		t.Run(string(dialect), func(t *testing.T) {
			q := getDialectQueries(dialect, "goauth_")
			if q == nil {
				t.Fatalf("getDialectQueries(%s) returned nil", dialect)
			}

			// Check all queries have content
			queries := map[string]string{
				"insertRefreshToken":         q.insertRefreshToken,
				"selectRefreshToken":         q.selectRefreshToken,
				"revokeRefreshToken":         q.revokeRefreshToken,
				"revokeTokenFamily":          q.revokeTokenFamily,
				"revokeAllUserRefreshTokens": q.revokeAllUserRefreshTokens,
				"deleteExpiredRefreshTokens": q.deleteExpiredRefreshTokens,
				"insertBlacklist":            q.insertBlacklist,
				"selectBlacklist":            q.selectBlacklist,
				"selectUserPermissions":      q.selectUserPermissions,
				"upsertUserPermissions":      q.upsertUserPermissions,
				"deleteUserPermissions":      q.deleteUserPermissions,
				"updateUsersWithRole":        q.updateUsersWithRole,
				"selectRoleTemplates":        q.selectRoleTemplates,
				"upsertRoleTemplate":         q.upsertRoleTemplate,
				"insertAPIKey":               q.insertAPIKey,
				"selectAPIKeyByHash":         q.selectAPIKeyByHash,
				"selectAPIKeysByUser":        q.selectAPIKeysByUser,
				"revokeAPIKey":               q.revokeAPIKey,
				"deleteExpiredAPIKeys":       q.deleteExpiredAPIKeys,
			}

			for name, query := range queries {
				if query == "" {
					t.Errorf("%s query is empty for dialect %s", name, dialect)
				}
			}
		})
	}
}
