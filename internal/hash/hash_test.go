package hash

import (
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "hello",
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			input:    "world",
			expected: "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7",
		},
		{
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SHA256(tt.input)
			if got != tt.expected {
				t.Errorf("SHA256(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSHA256_Consistent(t *testing.T) {
	input := "test-consistency"
	first := SHA256(input)

	for i := 0; i < 100; i++ {
		got := SHA256(input)
		if got != first {
			t.Error("SHA256 should produce consistent results")
		}
	}
}

func TestSHA256Bytes(t *testing.T) {
	input := "hello"
	got := SHA256Bytes(input)

	if len(got) != 32 {
		t.Errorf("len = %d, want 32", len(got))
	}

	// First byte of SHA256("hello")
	if got[0] != 0x2c {
		t.Errorf("first byte = %x, want 0x2c", got[0])
	}
}

func TestConstantTimeCompare(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected bool
	}{
		{"hello", "hello", true},
		{"hello", "world", false},
		{"", "", true},
		{"a", "ab", false},
		{"ab", "a", false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"-"+tt.b, func(t *testing.T) {
			got := ConstantTimeCompare(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("ConstantTimeCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestConstantTimeCompareBytes(t *testing.T) {
	tests := []struct {
		a        []byte
		b        []byte
		expected bool
	}{
		{[]byte("hello"), []byte("hello"), true},
		{[]byte("hello"), []byte("world"), false},
		{[]byte{}, []byte{}, true},
		{nil, nil, true},
		{[]byte("a"), []byte("ab"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.a)+"-"+string(tt.b), func(t *testing.T) {
			got := ConstantTimeCompareBytes(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("ConstantTimeCompareBytes() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Benchmark to verify constant time behavior
func BenchmarkConstantTimeCompare_Equal(b *testing.B) {
	s1 := "this-is-a-secret-token-12345678"
	s2 := "this-is-a-secret-token-12345678"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConstantTimeCompare(s1, s2)
	}
}

func BenchmarkConstantTimeCompare_NotEqual(b *testing.B) {
	s1 := "this-is-a-secret-token-12345678"
	s2 := "this-is-a-different-token-00000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConstantTimeCompare(s1, s2)
	}
}
