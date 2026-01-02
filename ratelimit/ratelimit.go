// Package ratelimit provides rate limiting for goauth.
package ratelimit

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Common errors
var (
	ErrRateLimited = errors.New("rate limit exceeded")
)

// Limiter defines the interface for rate limiters.
type Limiter interface {
	// Allow checks if a request is allowed for the given key.
	// Returns true if allowed, false if rate limited.
	Allow(ctx context.Context, key string) (bool, error)

	// AllowN checks if n requests are allowed for the given key.
	AllowN(ctx context.Context, key string, n int) (bool, error)

	// Reset resets the rate limit for the given key.
	Reset(ctx context.Context, key string) error

	// Close releases any resources held by the limiter.
	Close() error
}

// Config holds rate limiter configuration.
type Config struct {
	// Rate is the number of requests allowed per window.
	Rate int

	// Window is the time window for the rate limit.
	Window time.Duration

	// KeyFunc extracts the rate limit key from an HTTP request.
	// Defaults to client IP address.
	KeyFunc func(r *http.Request) string

	// OnLimited is called when a request is rate limited.
	// Defaults to returning 429 Too Many Requests.
	OnLimited func(w http.ResponseWriter, r *http.Request)

	// SkipFunc determines if a request should skip rate limiting.
	// Return true to skip.
	SkipFunc func(r *http.Request) bool

	// ExceedHandler is called when rate limit is exceeded.
	// If nil, uses OnLimited.
	ExceedHandler func(w http.ResponseWriter, r *http.Request, resetAt time.Time)
}

// DefaultConfig returns a default rate limiter configuration.
func DefaultConfig() *Config {
	return &Config{
		Rate:   100,
		Window: time.Minute,
		KeyFunc: func(r *http.Request) string {
			return GetClientIP(r)
		},
		OnLimited: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		},
	}
}

// GetClientIP extracts the client IP from an HTTP request.
// Checks X-Forwarded-For and X-Real-IP headers first.
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	// Strip port if present
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
		if addr[i] == ']' {
			// IPv6 address, already stripped
			break
		}
	}
	return addr
}

// entry represents a rate limit entry for a key.
type entry struct {
	count    int
	windowAt time.Time
}

// MemoryLimiter is an in-memory rate limiter using the sliding window algorithm.
type MemoryLimiter struct {
	mu      sync.RWMutex
	entries map[string]*entry
	rate    int
	window  time.Duration
	done    chan struct{}
}

// NewMemoryLimiter creates a new in-memory rate limiter.
func NewMemoryLimiter(rate int, window time.Duration) *MemoryLimiter {
	ml := &MemoryLimiter{
		entries: make(map[string]*entry),
		rate:    rate,
		window:  window,
		done:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go ml.cleanup()

	return ml
}

// Allow checks if a request is allowed for the given key.
func (m *MemoryLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return m.AllowN(ctx, key, 1)
}

// AllowN checks if n requests are allowed for the given key.
func (m *MemoryLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	e, exists := m.entries[key]

	if !exists || now.After(e.windowAt) {
		// New window
		m.entries[key] = &entry{
			count:    n,
			windowAt: now.Add(m.window),
		}
		return n <= m.rate, nil
	}

	// Within existing window
	if e.count+n > m.rate {
		return false, nil
	}

	e.count += n
	return true, nil
}

// Reset resets the rate limit for the given key.
func (m *MemoryLimiter) Reset(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

// Close stops the cleanup goroutine and releases resources.
func (m *MemoryLimiter) Close() error {
	close(m.done)
	return nil
}

// cleanup periodically removes expired entries.
func (m *MemoryLimiter) cleanup() {
	ticker := time.NewTicker(m.window)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.removeExpired()
		}
	}
}

// removeExpired removes all expired entries.
func (m *MemoryLimiter) removeExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, e := range m.entries {
		if now.After(e.windowAt) {
			delete(m.entries, key)
		}
	}
}

// GetRemainingRequests returns the number of requests remaining for a key.
func (m *MemoryLimiter) GetRemainingRequests(key string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, exists := m.entries[key]
	if !exists {
		return m.rate
	}

	if time.Now().After(e.windowAt) {
		return m.rate
	}

	remaining := m.rate - e.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// GetResetTime returns the time when the rate limit resets for a key.
func (m *MemoryLimiter) GetResetTime(key string) time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, exists := m.entries[key]
	if !exists {
		return time.Now().Add(m.window)
	}

	return e.windowAt
}

// Middleware creates an HTTP middleware that applies rate limiting.
func Middleware(limiter Limiter, cfg *Config) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	keyFunc := cfg.KeyFunc
	if keyFunc == nil {
		keyFunc = func(r *http.Request) string {
			return GetClientIP(r)
		}
	}

	onLimited := cfg.OnLimited
	if onLimited == nil {
		onLimited = func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request should skip rate limiting
			if cfg.SkipFunc != nil && cfg.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			key := keyFunc(r)
			allowed, err := limiter.Allow(r.Context(), key)
			if err != nil {
				// Log the error but allow the request to proceed
				log.Printf("[ratelimit] error checking rate limit for key %s: %v", key, err)
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				// Set rate limit headers if limiter supports it
				if ml, ok := limiter.(*MemoryLimiter); ok {
					resetAt := ml.GetResetTime(key)
					retryAfter := int(time.Until(resetAt).Seconds())
					if retryAfter < 0 {
						retryAfter = 0
					}
					w.Header().Set("X-RateLimit-Limit", strconv.Itoa(ml.rate))
					w.Header().Set("X-RateLimit-Remaining", "0")
					w.Header().Set("X-RateLimit-Reset", resetAt.Format(time.RFC3339))
					w.Header().Set("Retry-After", strconv.Itoa(retryAfter))

					if cfg.ExceedHandler != nil {
						cfg.ExceedHandler(w, r, resetAt)
						return
					}
				}

				onLimited(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SlidingWindowLimiter implements a sliding window rate limiter.
// It provides more accurate rate limiting than fixed window.
type SlidingWindowLimiter struct {
	mu      sync.RWMutex
	entries map[string]*slidingEntry
	rate    int
	window  time.Duration
	done    chan struct{}
}

type slidingEntry struct {
	prevCount int
	currCount int
	windowAt  time.Time
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter.
func NewSlidingWindowLimiter(rate int, window time.Duration) *SlidingWindowLimiter {
	sl := &SlidingWindowLimiter{
		entries: make(map[string]*slidingEntry),
		rate:    rate,
		window:  window,
		done:    make(chan struct{}),
	}

	go sl.cleanup()
	return sl
}

// Allow checks if a request is allowed for the given key.
func (s *SlidingWindowLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return s.AllowN(ctx, key, 1)
}

// AllowN checks if n requests are allowed for the given key.
func (s *SlidingWindowLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	e, exists := s.entries[key]

	if !exists {
		s.entries[key] = &slidingEntry{
			prevCount: 0,
			currCount: n,
			windowAt:  now.Add(s.window),
		}
		return n <= s.rate, nil
	}

	// Check if we need to rotate windows
	if now.After(e.windowAt) {
		// Calculate how many windows have passed
		windowsPassed := int(now.Sub(e.windowAt) / s.window)
		if windowsPassed >= 2 {
			// Two or more windows passed, reset
			e.prevCount = 0
			e.currCount = n
		} else {
			// Rotate window
			e.prevCount = e.currCount
			e.currCount = n
		}
		e.windowAt = now.Add(s.window)
		return n <= s.rate, nil
	}

	// Calculate weighted count using sliding window
	// Weight is based on how far we are into the current window
	elapsed := s.window - time.Until(e.windowAt)
	weight := float64(s.window-elapsed) / float64(s.window)
	weightedCount := float64(e.prevCount)*weight + float64(e.currCount)

	if int(weightedCount)+n > s.rate {
		return false, nil
	}

	e.currCount += n
	return true, nil
}

// Reset resets the rate limit for the given key.
func (s *SlidingWindowLimiter) Reset(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	return nil
}

// Close stops the cleanup goroutine and releases resources.
func (s *SlidingWindowLimiter) Close() error {
	close(s.done)
	return nil
}

// cleanup periodically removes expired entries.
func (s *SlidingWindowLimiter) cleanup() {
	ticker := time.NewTicker(s.window)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.removeExpired()
		}
	}
}

// removeExpired removes entries that have been expired for more than 2 windows.
func (s *SlidingWindowLimiter) removeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	threshold := now.Add(-2 * s.window)
	for key, e := range s.entries {
		if e.windowAt.Before(threshold) {
			delete(s.entries, key)
		}
	}
}

// TokenBucketLimiter implements the token bucket algorithm.
type TokenBucketLimiter struct {
	mu       sync.RWMutex
	buckets  map[string]*bucket
	capacity int
	rate     float64 // tokens per second
	done     chan struct{}
}

type bucket struct {
	tokens   float64
	lastTime time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter.
// capacity is the maximum number of tokens in the bucket.
// rate is the number of tokens added per second.
func NewTokenBucketLimiter(capacity int, rate float64) *TokenBucketLimiter {
	tb := &TokenBucketLimiter{
		buckets:  make(map[string]*bucket),
		capacity: capacity,
		rate:     rate,
		done:     make(chan struct{}),
	}

	go tb.cleanup()
	return tb
}

// Allow checks if a request is allowed for the given key.
func (t *TokenBucketLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return t.AllowN(ctx, key, 1)
}

// AllowN checks if n requests are allowed for the given key.
func (t *TokenBucketLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	b, exists := t.buckets[key]

	if !exists {
		t.buckets[key] = &bucket{
			tokens:   float64(t.capacity - n),
			lastTime: now,
		}
		return n <= t.capacity, nil
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * t.rate
	if b.tokens > float64(t.capacity) {
		b.tokens = float64(t.capacity)
	}
	b.lastTime = now

	if b.tokens < float64(n) {
		return false, nil
	}

	b.tokens -= float64(n)
	return true, nil
}

// Reset resets the rate limit for the given key.
func (t *TokenBucketLimiter) Reset(ctx context.Context, key string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.buckets, key)
	return nil
}

// Close stops the cleanup goroutine and releases resources.
func (t *TokenBucketLimiter) Close() error {
	close(t.done)
	return nil
}

// cleanup periodically removes stale buckets.
func (t *TokenBucketLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.removeStale()
		}
	}
}

// removeStale removes buckets that haven't been used in a while.
func (t *TokenBucketLimiter) removeStale() {
	t.mu.Lock()
	defer t.mu.Unlock()

	threshold := time.Now().Add(-5 * time.Minute)
	for key, b := range t.buckets {
		if b.lastTime.Before(threshold) {
			delete(t.buckets, key)
		}
	}
}
