package password

import (
	"strings"
	"testing"
)

func TestArgon2Hasher_Hash(t *testing.T) {
	h := NewArgon2Hasher(nil)

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash should start with $argon2id$, got: %s", hash)
	}

	// Hash should have 6 parts when split by $
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("expected 6 parts, got %d", len(parts))
	}
}

func TestArgon2Hasher_HashUnique(t *testing.T) {
	h := NewArgon2Hasher(nil)

	hash1, _ := h.Hash("password123")
	hash2, _ := h.Hash("password123")

	if hash1 == hash2 {
		t.Error("hashes should be unique due to random salt")
	}
}

func TestArgon2Hasher_Verify(t *testing.T) {
	h := NewArgon2Hasher(nil)

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

func TestArgon2Hasher_VerifyInvalidHash(t *testing.T) {
	h := NewArgon2Hasher(nil)

	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"invalid format", "not-a-hash"},
		{"wrong algorithm", "$bcrypt$..."},
		{"missing parts", "$argon2id$v=19$m=65536"},
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

func TestArgon2Hasher_NeedsRehash(t *testing.T) {
	// Create hasher with default config
	h := NewArgon2Hasher(nil)
	hash, _ := h.Hash("password123")

	// Same config should not need rehash
	if h.NeedsRehash(hash) {
		t.Error("hash with same config should not need rehash")
	}

	// Different config should need rehash
	differentConfig := &Argon2Config{
		Memory:      32 * 1024, // Different memory
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	h2 := NewArgon2Hasher(differentConfig)
	if !h2.NeedsRehash(hash) {
		t.Error("hash with different config should need rehash")
	}
}

func TestArgon2Hasher_NeedsRehashInvalidHash(t *testing.T) {
	h := NewArgon2Hasher(nil)

	if !h.NeedsRehash("invalid-hash") {
		t.Error("invalid hash should need rehash")
	}
}

func TestArgon2Hasher_CustomConfig(t *testing.T) {
	config := &Argon2Config{
		Memory:      32 * 1024,
		Iterations:  2,
		Parallelism: 1,
		SaltLength:  32,
		KeyLength:   64,
	}
	h := NewArgon2Hasher(config)

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	valid, err := h.Verify("password123", hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("password should be valid")
	}

	// Check that the hash contains the custom memory value
	if !strings.Contains(hash, "m=32768") {
		t.Error("hash should contain custom memory parameter")
	}
}

func TestDefaultArgon2Config(t *testing.T) {
	config := DefaultArgon2Config()

	if config.Memory != 64*1024 {
		t.Errorf("expected memory 64*1024, got %d", config.Memory)
	}
	if config.Iterations != 3 {
		t.Errorf("expected iterations 3, got %d", config.Iterations)
	}
	if config.Parallelism != 2 {
		t.Errorf("expected parallelism 2, got %d", config.Parallelism)
	}
	if config.SaltLength != 16 {
		t.Errorf("expected salt length 16, got %d", config.SaltLength)
	}
	if config.KeyLength != 32 {
		t.Errorf("expected key length 32, got %d", config.KeyLength)
	}
}

func TestArgon2Hasher_EmptyPassword(t *testing.T) {
	h := NewArgon2Hasher(nil)

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

func TestArgon2Hasher_LongPassword(t *testing.T) {
	h := NewArgon2Hasher(nil)

	// Very long password
	longPassword := strings.Repeat("a", 1000)

	hash, err := h.Hash(longPassword)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	valid, err := h.Verify(longPassword, hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("long password should verify")
	}
}

func TestArgon2Hasher_UnicodePassword(t *testing.T) {
	h := NewArgon2Hasher(nil)

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
