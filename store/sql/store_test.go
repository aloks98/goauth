package sql

import (
	"testing"
)

func TestNew(t *testing.T) {
	// Test that New returns an error when no DB is provided and DSN is empty
	cfg := &Config{
		Dialect: PostgreSQL,
	}

	_, err := New(cfg)
	if err == nil {
		t.Error("expected error when no DB or DSN provided")
	}
}

func TestGetDriverName(t *testing.T) {
	tests := []struct {
		dialect  Dialect
		expected string
	}{
		{PostgreSQL, "postgres"},
		{MySQL, "mysql"},
		{Dialect("unknown"), "postgres"}, // defaults to postgres
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
	pgQueries := getDialectQueries(PostgreSQL)
	if pgQueries == nil {
		t.Fatal("getDialectQueries(PostgreSQL) returned nil")
	}
	if pgQueries.placeholder(1) != "$1" {
		t.Errorf("PostgreSQL placeholder(1) = %q, want $1", pgQueries.placeholder(1))
	}

	mysqlQueries := getDialectQueries(MySQL)
	if mysqlQueries == nil {
		t.Fatal("getDialectQueries(MySQL) returned nil")
	}
	if mysqlQueries.placeholder(1) != "?" {
		t.Errorf("MySQL placeholder(1) = %q, want ?", mysqlQueries.placeholder(1))
	}

	// Unknown dialect defaults to PostgreSQL
	unknownQueries := getDialectQueries(Dialect("unknown"))
	if unknownQueries == nil {
		t.Fatal("getDialectQueries(unknown) returned nil")
	}
	if unknownQueries.placeholder(1) != "$1" {
		t.Errorf("unknown dialect placeholder(1) = %q, want $1", unknownQueries.placeholder(1))
	}
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
