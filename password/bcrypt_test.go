package password

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHasher_Hash(t *testing.T) {
	h := NewBcryptHasher(nil)

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Errorf("hash should start with $2a$ or $2b$, got: %s", hash)
	}
}

func TestBcryptHasher_HashUnique(t *testing.T) {
	h := NewBcryptHasher(nil)

	hash1, _ := h.Hash("password123")
	hash2, _ := h.Hash("password123")

	if hash1 == hash2 {
		t.Error("hashes should be unique due to random salt")
	}
}

func TestBcryptHasher_Verify(t *testing.T) {
	h := NewBcryptHasher(nil)

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"correct password", "password123", true},
		{"wrong password", "wrongpassword", false},
		{"empty password", "", false},
		{"similar password", "password124", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := h.Verify(tt.password, hash)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if valid != tt.want {
				t.Errorf("Verify(%q) = %v, want %v", tt.password, valid, tt.want)
			}
		})
	}
}

func TestBcryptHasher_VerifyInvalidHash(t *testing.T) {
	h := NewBcryptHasher(nil)

	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"invalid format", "not-a-hash"},
		{"too short", "$2a$12$abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.Verify("password", tt.hash)
			if err == nil {
				t.Error("expected error for invalid hash")
			}
		})
	}
}

func TestBcryptHasher_NeedsRehash(t *testing.T) {
	// Create hasher with cost 10
	h := NewBcryptHasher(&BcryptConfig{Cost: 10})
	hash, _ := h.Hash("password123")

	// Same cost should not need rehash
	if h.NeedsRehash(hash) {
		t.Error("hash with same cost should not need rehash")
	}

	// Different cost should need rehash
	h2 := NewBcryptHasher(&BcryptConfig{Cost: 12})
	if !h2.NeedsRehash(hash) {
		t.Error("hash with different cost should need rehash")
	}
}

func TestBcryptHasher_NeedsRehashInvalidHash(t *testing.T) {
	h := NewBcryptHasher(nil)

	if !h.NeedsRehash("invalid-hash") {
		t.Error("invalid hash should need rehash")
	}
}

func TestBcryptHasher_CustomConfig(t *testing.T) {
	config := &BcryptConfig{Cost: 10}
	h := NewBcryptHasher(config)

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the cost is correct
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("unexpected error getting cost: %v", err)
	}
	if cost != 10 {
		t.Errorf("expected cost 10, got %d", cost)
	}
}

func TestBcryptHasher_CostClamping(t *testing.T) {
	// Test minimum cost clamping
	h := NewBcryptHasher(&BcryptConfig{Cost: 1})
	hash, _ := h.Hash("password123")
	cost, _ := bcrypt.Cost([]byte(hash))
	if cost < bcrypt.MinCost {
		t.Errorf("cost should be at least %d, got %d", bcrypt.MinCost, cost)
	}

	// Test maximum cost clamping (we won't actually test MaxCost as it's very slow)
	h2 := NewBcryptHasher(&BcryptConfig{Cost: 100})
	if h2.config.Cost != bcrypt.MaxCost {
		t.Errorf("cost should be clamped to %d, got %d", bcrypt.MaxCost, h2.config.Cost)
	}
}

func TestDefaultBcryptConfig(t *testing.T) {
	config := DefaultBcryptConfig()

	if config.Cost != 12 {
		t.Errorf("expected cost 12, got %d", config.Cost)
	}
}

func TestBcryptHasher_EmptyPassword(t *testing.T) {
	h := NewBcryptHasher(nil)

	// Empty password should still hash
	hash, err := h.Hash("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	valid, err := h.Verify("", hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("empty password should verify")
	}
}

func TestBcryptHasher_LongPassword(t *testing.T) {
	h := NewBcryptHasher(nil)

	// Bcrypt has a 72-byte limit, test at that boundary
	maxPassword := strings.Repeat("a", 72)

	hash, err := h.Hash(maxPassword)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	valid, err := h.Verify(maxPassword, hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("max length password should verify")
	}
}

func TestBcryptHasher_PasswordTooLong(t *testing.T) {
	h := NewBcryptHasher(nil)

	// Bcrypt rejects passwords > 72 bytes
	tooLongPassword := strings.Repeat("a", 73)

	_, err := h.Hash(tooLongPassword)
	if err == nil {
		t.Error("expected error for password > 72 bytes")
	}
}

func TestBcryptHasher_UnicodePassword(t *testing.T) {
	h := NewBcryptHasher(nil)

	unicodePassword := "пароль密码🔐"

	hash, err := h.Hash(unicodePassword)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	valid, err := h.Verify(unicodePassword, hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("unicode password should verify")
	}
}

func TestBcryptHasher_NilConfig(t *testing.T) {
	h := NewBcryptHasher(nil)

	if h.config.Cost != 12 {
		t.Errorf("nil config should use default cost 12, got %d", h.config.Cost)
	}
}
