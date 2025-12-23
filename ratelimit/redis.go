package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisLimiter is a Redis-backed rate limiter using the sliding window algorithm.
// Suitable for distributed systems.
type RedisLimiter struct {
	client    redis.Cmdable
	keyPrefix string
	rate      int
	window    time.Duration
}

// RedisConfig holds Redis rate limiter configuration.
type RedisConfig struct {
	// Client is the Redis client to use.
	Client redis.Cmdable

	// KeyPrefix is the prefix for all rate limit keys.
	// Defaults to "ratelimit:".
	KeyPrefix string

	// Rate is the number of requests allowed per window.
	Rate int

	// Window is the time window for the rate limit.
	Window time.Duration
}

// NewRedisLimiter creates a new Redis-backed rate limiter.
func NewRedisLimiter(cfg *RedisConfig) *RedisLimiter {
	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "ratelimit:"
	}

	return &RedisLimiter{
		client:    cfg.Client,
		keyPrefix: keyPrefix,
		rate:      cfg.Rate,
		window:    cfg.Window,
	}
}

// Allow checks if a request is allowed for the given key.
func (r *RedisLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return r.AllowN(ctx, key, 1)
}

// AllowN checks if n requests are allowed for the given key.
// Uses a sliding window implemented with Redis sorted sets.
func (r *RedisLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	redisKey := r.keyPrefix + key
	now := time.Now()
	windowStart := now.Add(-r.window).UnixMicro()
	nowMicro := now.UnixMicro()

	// Use a Lua script for atomic sliding window rate limiting
	script := redis.NewScript(`
		local key = KEYS[1]
		local window_start = tonumber(ARGV[1])
		local now = tonumber(ARGV[2])
		local rate = tonumber(ARGV[3])
		local n = tonumber(ARGV[4])
		local window_ms = tonumber(ARGV[5])

		-- Remove old entries
		redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

		-- Count current entries
		local count = redis.call('ZCARD', key)

		if count + n > rate then
			return 0
		end

		-- Add new entries
		for i = 1, n do
			redis.call('ZADD', key, now + i - 1, now .. ':' .. i)
		end

		-- Set expiry
		redis.call('PEXPIRE', key, window_ms)

		return 1
	`)

	result, err := script.Run(ctx, r.client, []string{redisKey},
		windowStart,
		nowMicro,
		r.rate,
		n,
		r.window.Milliseconds(),
	).Int()

	if err != nil {
		return false, fmt.Errorf("redis rate limit script failed: %w", err)
	}

	return result == 1, nil
}

// Reset resets the rate limit for the given key.
func (r *RedisLimiter) Reset(ctx context.Context, key string) error {
	redisKey := r.keyPrefix + key
	return r.client.Del(ctx, redisKey).Err()
}

// Close is a no-op for Redis limiter as the client is managed externally.
func (r *RedisLimiter) Close() error {
	return nil
}

// GetRemainingRequests returns the number of requests remaining for a key.
func (r *RedisLimiter) GetRemainingRequests(ctx context.Context, key string) (int, error) {
	redisKey := r.keyPrefix + key
	now := time.Now()
	windowStart := now.Add(-r.window).UnixMicro()

	// Remove old entries and count
	pipe := r.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, redisKey, "-inf", strconv.FormatInt(windowStart, 10))
	countCmd := pipe.ZCard(ctx, redisKey)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	count := countCmd.Val()
	remaining := r.rate - int(count)
	if remaining < 0 {
		return 0, nil
	}
	return remaining, nil
}

// RedisTokenBucketLimiter implements token bucket algorithm with Redis.
type RedisTokenBucketLimiter struct {
	client    redis.Cmdable
	keyPrefix string
	capacity  int
	rate      float64 // tokens per second
}

// NewRedisTokenBucketLimiter creates a new Redis-backed token bucket limiter.
func NewRedisTokenBucketLimiter(client redis.Cmdable, keyPrefix string, capacity int, rate float64) *RedisTokenBucketLimiter {
	if keyPrefix == "" {
		keyPrefix = "ratelimit:tb:"
	}
	return &RedisTokenBucketLimiter{
		client:    client,
		keyPrefix: keyPrefix,
		capacity:  capacity,
		rate:      rate,
	}
}

// Allow checks if a request is allowed for the given key.
func (r *RedisTokenBucketLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return r.AllowN(ctx, key, 1)
}

// AllowN checks if n requests are allowed for the given key.
func (r *RedisTokenBucketLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	redisKey := r.keyPrefix + key
	now := time.Now().UnixMicro()

	// Lua script for atomic token bucket
	script := redis.NewScript(`
		local key = KEYS[1]
		local capacity = tonumber(ARGV[1])
		local rate = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])
		local requested = tonumber(ARGV[4])

		local bucket = redis.call('HMGET', key, 'tokens', 'last_time')
		local tokens = tonumber(bucket[1])
		local last_time = tonumber(bucket[2])

		if tokens == nil then
			tokens = capacity
			last_time = now
		end

		-- Calculate tokens to add based on elapsed time
		local elapsed = (now - last_time) / 1000000.0  -- convert from microseconds to seconds
		tokens = tokens + (elapsed * rate)
		if tokens > capacity then
			tokens = capacity
		end

		if tokens < requested then
			-- Update last_time even on failure to prevent token explosion
			redis.call('HMSET', key, 'tokens', tokens, 'last_time', now)
			redis.call('EXPIRE', key, 300)  -- 5 minute expiry
			return 0
		end

		tokens = tokens - requested
		redis.call('HMSET', key, 'tokens', tokens, 'last_time', now)
		redis.call('EXPIRE', key, 300)  -- 5 minute expiry

		return 1
	`)

	result, err := script.Run(ctx, r.client, []string{redisKey},
		r.capacity,
		r.rate,
		now,
		n,
	).Int()

	if err != nil {
		return false, fmt.Errorf("redis token bucket script failed: %w", err)
	}

	return result == 1, nil
}

// Reset resets the rate limit for the given key.
func (r *RedisTokenBucketLimiter) Reset(ctx context.Context, key string) error {
	redisKey := r.keyPrefix + key
	return r.client.Del(ctx, redisKey).Err()
}

// Close is a no-op for Redis limiter.
func (r *RedisTokenBucketLimiter) Close() error {
	return nil
}

// RedisFixedWindowLimiter implements a simple fixed window rate limiter with Redis.
// Simpler and more efficient than sliding window, but less accurate.
type RedisFixedWindowLimiter struct {
	client    redis.Cmdable
	keyPrefix string
	rate      int
	window    time.Duration
}

// NewRedisFixedWindowLimiter creates a new Redis fixed window limiter.
func NewRedisFixedWindowLimiter(client redis.Cmdable, keyPrefix string, rate int, window time.Duration) *RedisFixedWindowLimiter {
	if keyPrefix == "" {
		keyPrefix = "ratelimit:fw:"
	}
	return &RedisFixedWindowLimiter{
		client:    client,
		keyPrefix: keyPrefix,
		rate:      rate,
		window:    window,
	}
}

// Allow checks if a request is allowed for the given key.
func (r *RedisFixedWindowLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return r.AllowN(ctx, key, 1)
}

// AllowN checks if n requests are allowed for the given key.
func (r *RedisFixedWindowLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	// Use window timestamp as part of key for fixed windows
	windowID := time.Now().Truncate(r.window).Unix()
	redisKey := fmt.Sprintf("%s%s:%d", r.keyPrefix, key, windowID)

	// Use INCRBY and check limit
	pipe := r.client.Pipeline()
	incrCmd := pipe.IncrBy(ctx, redisKey, int64(n))
	pipe.Expire(ctx, redisKey, r.window+time.Second) // +1s buffer

	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}

	count := incrCmd.Val()
	if count > int64(r.rate) {
		// Already exceeded, but we've already incremented
		// This is a slight over-count but acceptable for simplicity
		return false, nil
	}

	return true, nil
}

// Reset resets the rate limit for the given key.
func (r *RedisFixedWindowLimiter) Reset(ctx context.Context, key string) error {
	// Reset current window
	windowID := time.Now().Truncate(r.window).Unix()
	redisKey := fmt.Sprintf("%s%s:%d", r.keyPrefix, key, windowID)
	return r.client.Del(ctx, redisKey).Err()
}

// Close is a no-op for Redis limiter.
func (r *RedisFixedWindowLimiter) Close() error {
	return nil
}
