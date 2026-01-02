package goauth

import (
	"context"
	"testing"

	"github.com/aloks98/goauth/internal/testutil"
)

func BenchmarkGenerateTokenPair(b *testing.B) {
	store := testutil.SetupPostgres(b)

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()
	claims := map[string]any{"role": "admin"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := auth.GenerateTokenPair(ctx, "user123", claims)
		if err != nil {
			b.Fatalf("GenerateTokenPair() error = %v", err)
		}
	}
}

func BenchmarkValidateAccessToken(b *testing.B) {
	store := testutil.SetupPostgres(b)

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()
	pair, err := auth.GenerateTokenPair(ctx, "user123", nil)
	if err != nil {
		b.Fatalf("GenerateTokenPair() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := auth.ValidateAccessToken(ctx, pair.AccessToken)
		if err != nil {
			b.Fatalf("ValidateAccessToken() error = %v", err)
		}
	}
}

func BenchmarkRefreshTokens(b *testing.B) {
	store := testutil.SetupPostgres(b)

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pair, _ := auth.GenerateTokenPair(ctx, "user123", nil)
		b.StartTimer()

		_, err := auth.RefreshTokens(ctx, pair.RefreshToken)
		if err != nil {
			b.Fatalf("RefreshTokens() error = %v", err)
		}
	}
}

func BenchmarkCreateAPIKey(b *testing.B) {
	store := testutil.SetupPostgres(b)

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := auth.CreateAPIKey(ctx, "user123", nil)
		if err != nil {
			b.Fatalf("CreateAPIKey() error = %v", err)
		}
	}
}

func BenchmarkValidateAPIKey(b *testing.B) {
	store := testutil.SetupPostgres(b)

	auth, err := New[*TestClaims](
		WithSecret("this-is-a-32-character-secret!!!"),
		WithStore(store),
	)
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer auth.Close()

	ctx := context.Background()
	result, err := auth.CreateAPIKey(ctx, "user123", nil)
	if err != nil {
		b.Fatalf("CreateAPIKey() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := auth.ValidateAPIKey(ctx, result.RawKey)
		if err != nil {
			b.Fatalf("ValidateAPIKey() error = %v", err)
		}
	}
}
