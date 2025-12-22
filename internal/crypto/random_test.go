package crypto

import (
	"strings"
	"testing"
)

func TestGenerateRandomBytes(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := GenerateRandomBytes(tt.length)
			if err != nil {
				t.Fatalf("GenerateRandomBytes() error = %v", err)
			}
			if len(b) != tt.length {
				t.Errorf("len = %d, want %d", len(b), tt.length)
			}
		})
	}
}

func TestGenerateRandomBytes_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		b, err := GenerateRandomBytes(16)
		if err != nil {
			t.Fatalf("GenerateRandomBytes() error = %v", err)
		}
		s := string(b)
		if seen[s] {
			t.Error("Generated duplicate random bytes")
		}
		seen[s] = true
	}
}

func TestGenerateRandomString(t *testing.T) {
	s, err := GenerateRandomString(32)
	if err != nil {
		t.Fatalf("GenerateRandomString() error = %v", err)
	}

	// Base64 encoding of 32 bytes should be ~44 characters
	if len(s) < 40 {
		t.Errorf("len = %d, expected >= 40", len(s))
	}
}

func TestGenerateRandomString_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		s, err := GenerateRandomString(16)
		if err != nil {
			t.Fatalf("GenerateRandomString() error = %v", err)
		}
		if seen[s] {
			t.Error("Generated duplicate random string")
		}
		seen[s] = true
	}
}

func TestGenerateRandomHex(t *testing.T) {
	s, err := GenerateRandomHex(16)
	if err != nil {
		t.Fatalf("GenerateRandomHex() error = %v", err)
	}

	// 16 bytes = 32 hex characters
	if len(s) != 32 {
		t.Errorf("len = %d, want 32", len(s))
	}

	// Should only contain hex characters
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			t.Errorf("invalid hex character: %c", c)
		}
	}
}

func TestGenerateID(t *testing.T) {
	id, err := GenerateID()
	if err != nil {
		t.Fatalf("GenerateID() error = %v", err)
	}

	// Should be 32 hex characters (16 bytes)
	if len(id) != 32 {
		t.Errorf("len = %d, want 32", len(id))
	}
}

func TestGenerateID_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		id, err := GenerateID()
		if err != nil {
			t.Fatalf("GenerateID() error = %v", err)
		}
		if seen[id] {
			t.Error("Generated duplicate ID")
		}
		seen[id] = true
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key, err := GenerateAPIKey("sk_live", 32)
	if err != nil {
		t.Fatalf("GenerateAPIKey() error = %v", err)
	}

	if !strings.HasPrefix(key, "sk_live_") {
		t.Errorf("key = %q, should start with 'sk_live_'", key)
	}

	// sk_live_ (8) + 64 hex chars (32 bytes)
	if len(key) != 8+64 {
		t.Errorf("len = %d, want %d", len(key), 8+64)
	}
}

func TestGenerateAPIKey_UniqueValues(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		key, err := GenerateAPIKey("sk", 16)
		if err != nil {
			t.Fatalf("GenerateAPIKey() error = %v", err)
		}
		if seen[key] {
			t.Error("Generated duplicate API key")
		}
		seen[key] = true
	}
}
