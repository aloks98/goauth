package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMemoryLimiter_Allow(t *testing.T) {
	limiter := NewMemoryLimiter(5, time.Minute)
	defer limiter.Close()

	ctx := context.Background()

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		allowed, err := limiter.Allow(ctx, "user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	allowed, err := limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("6th request should be denied")
	}
}

func TestMemoryLimiter_DifferentKeys(t *testing.T) {
	limiter := NewMemoryLimiter(2, time.Minute)
	defer limiter.Close()

	ctx := context.Background()

	// user1 uses 2 requests
	limiter.Allow(ctx, "user1")
	limiter.Allow(ctx, "user1")

	// user1 should be denied
	allowed, _ := limiter.Allow(ctx, "user1")
	if allowed {
		t.Error("user1 should be denied")
	}

	// user2 should still be allowed
	allowed, _ = limiter.Allow(ctx, "user2")
	if !allowed {
		t.Error("user2 should be allowed")
	}
}

func TestMemoryLimiter_Reset(t *testing.T) {
	limiter := NewMemoryLimiter(2, time.Minute)
	defer limiter.Close()

	ctx := context.Background()

	// Use up the limit
	limiter.Allow(ctx, "user1")
	limiter.Allow(ctx, "user1")

	allowed, _ := limiter.Allow(ctx, "user1")
	if allowed {
		t.Error("should be denied before reset")
	}

	// Reset
	limiter.Reset(ctx, "user1")

	// Should be allowed again
	allowed, _ = limiter.Allow(ctx, "user1")
	if !allowed {
		t.Error("should be allowed after reset")
	}
}

func TestMemoryLimiter_WindowReset(t *testing.T) {
	limiter := NewMemoryLimiter(2, 50*time.Millisecond)
	defer limiter.Close()

	ctx := context.Background()

	// Use up the limit
	limiter.Allow(ctx, "user1")
	limiter.Allow(ctx, "user1")

	allowed, _ := limiter.Allow(ctx, "user1")
	if allowed {
		t.Error("should be denied")
	}

	// Wait for window to reset
	time.Sleep(60 * time.Millisecond)

	// Should be allowed in new window
	allowed, _ = limiter.Allow(ctx, "user1")
	if !allowed {
		t.Error("should be allowed in new window")
	}
}

func TestMemoryLimiter_AllowN(t *testing.T) {
	limiter := NewMemoryLimiter(10, time.Minute)
	defer limiter.Close()

	ctx := context.Background()

	// Request 5 at once
	allowed, _ := limiter.AllowN(ctx, "user1", 5)
	if !allowed {
		t.Error("5 requests should be allowed")
	}

	// Request 5 more
	allowed, _ = limiter.AllowN(ctx, "user1", 5)
	if !allowed {
		t.Error("another 5 should be allowed")
	}

	// Request 1 more should fail
	allowed, _ = limiter.AllowN(ctx, "user1", 1)
	if allowed {
		t.Error("should be denied at limit")
	}
}

func TestMemoryLimiter_GetRemainingRequests(t *testing.T) {
	limiter := NewMemoryLimiter(5, time.Minute)
	defer limiter.Close()

	ctx := context.Background()

	// Initially should have full capacity
	remaining := limiter.GetRemainingRequests("user1")
	if remaining != 5 {
		t.Errorf("expected 5 remaining, got %d", remaining)
	}

	// Use 3 requests
	limiter.Allow(ctx, "user1")
	limiter.Allow(ctx, "user1")
	limiter.Allow(ctx, "user1")

	remaining = limiter.GetRemainingRequests("user1")
	if remaining != 2 {
		t.Errorf("expected 2 remaining, got %d", remaining)
	}
}

func TestSlidingWindowLimiter_Allow(t *testing.T) {
	limiter := NewSlidingWindowLimiter(5, time.Minute)
	defer limiter.Close()

	ctx := context.Background()

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		allowed, err := limiter.Allow(ctx, "user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	allowed, err := limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("6th request should be denied")
	}
}

func TestTokenBucketLimiter_Allow(t *testing.T) {
	// 5 tokens capacity, 10 tokens per second refill
	limiter := NewTokenBucketLimiter(5, 10)
	defer limiter.Close()

	ctx := context.Background()

	// First 5 requests should be allowed (initial capacity)
	for i := 0; i < 5; i++ {
		allowed, err := limiter.Allow(ctx, "user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied (bucket empty)
	allowed, err := limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("6th request should be denied")
	}

	// Wait for bucket to refill
	time.Sleep(200 * time.Millisecond)

	// Should be allowed again after refill
	allowed, _ = limiter.Allow(ctx, "user1")
	if !allowed {
		t.Error("should be allowed after refill")
	}
}

func TestMiddleware(t *testing.T) {
	limiter := NewMemoryLimiter(2, time.Minute)
	defer limiter.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := &Config{
		KeyFunc: func(r *http.Request) string {
			return "test-key"
		},
	}

	middleware := Middleware(limiter, cfg)
	wrappedHandler := middleware(handler)

	// First 2 requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func TestMiddleware_SkipFunc(t *testing.T) {
	limiter := NewMemoryLimiter(1, time.Minute)
	defer limiter.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := &Config{
		SkipFunc: func(r *http.Request) bool {
			return r.URL.Path == "/health"
		},
	}

	middleware := Middleware(limiter, cfg)
	wrappedHandler := middleware(handler)

	// Use up the limit
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	// Verify limit is used
	req = httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	w = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Error("expected rate limit for /api/resource")
	}

	// Health check should bypass rate limit
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("health check should bypass rate limit, got %d", w.Code)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expected      string
	}{
		{
			name:       "remote addr only",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:          "X-Forwarded-For single",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "203.0.113.195",
			expected:      "203.0.113.195",
		},
		{
			name:          "X-Forwarded-For multiple",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "203.0.113.195, 70.41.3.18, 150.172.238.178",
			expected:      "203.0.113.195",
		},
		{
			name:       "X-Real-IP",
			remoteAddr: "10.0.0.1:12345",
			xRealIP:    "203.0.113.195",
			expected:   "203.0.113.195",
		},
		{
			name:          "X-Forwarded-For takes precedence",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "203.0.113.195",
			xRealIP:       "70.41.3.18",
			expected:      "203.0.113.195",
		},
		{
			name:       "IPv6 remote addr",
			remoteAddr: "[::1]:12345",
			expected:   "[::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := GetClientIP(req)
			if ip != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, ip)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Rate != 100 {
		t.Errorf("expected rate 100, got %d", cfg.Rate)
	}
	if cfg.Window != time.Minute {
		t.Errorf("expected window 1m, got %v", cfg.Window)
	}
	if cfg.KeyFunc == nil {
		t.Error("expected KeyFunc to be set")
	}
	if cfg.OnLimited == nil {
		t.Error("expected OnLimited to be set")
	}
}

func BenchmarkMemoryLimiter_Allow(b *testing.B) {
	limiter := NewMemoryLimiter(1000000, time.Hour)
	defer limiter.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow(ctx, "user1")
	}
}

func BenchmarkSlidingWindowLimiter_Allow(b *testing.B) {
	limiter := NewSlidingWindowLimiter(1000000, time.Hour)
	defer limiter.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow(ctx, "user1")
	}
}

func BenchmarkTokenBucketLimiter_Allow(b *testing.B) {
	limiter := NewTokenBucketLimiter(1000000, 1000000)
	defer limiter.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow(ctx, "user1")
	}
}
