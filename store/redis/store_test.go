package redis

import (
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestNew(t *testing.T) {
	// Test with provided client
	mockClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer mockClient.Close()

	cfg := &Config{
		Client: mockClient,
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if s == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_WithAddr(t *testing.T) {
	cfg := &Config{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
		PoolSize: 10,
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if s == nil {
		t.Fatal("New() returned nil")
	}
	s.Close()
}

func TestKeyPrefixes(t *testing.T) {
	// Verify key prefixes are properly defined
	prefixes := []string{
		prefixRefreshToken,
		prefixTokenFamily,
		prefixUserTokens,
		prefixBlacklist,
		prefixUserPerms,
		prefixUsersByRole,
		prefixRoleTemplate,
		prefixRoleTemplates,
		prefixAPIKey,
		prefixAPIKeyByHash,
		prefixUserAPIKeys,
		prefixAPIKeyExpiries,
	}

	for _, prefix := range prefixes {
		if prefix == "" {
			t.Error("empty prefix found")
		}
		if prefix[:7] != "goauth:" {
			t.Errorf("prefix %q doesn't start with 'goauth:'", prefix)
		}
	}
}

func TestStrconv(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{123, "123"},
		{-1, "-1"},
		{-123, "-123"},
		{1234567890, "1234567890"},
	}

	for _, tt := range tests {
		got := strconv(tt.input)
		if got != tt.expected {
			t.Errorf("strconv(%v) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestFormatFloat(t *testing.T) {
	// formatFloat just wraps strconv
	result := formatFloat(12345)
	if result != "12345" {
		t.Errorf("formatFloat(12345) = %q, want \"12345\"", result)
	}
}
