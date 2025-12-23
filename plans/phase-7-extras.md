# Phase 7: Rate Limiting & Cleanup

**Duration:** 2-3 days
**Goal:** Implement optional rate limiting and background cleanup workers.

**Dependencies:** Phase 1 (Foundation), Phase 5 (Store)

---

## Tasks

### 7.1 Rate Limiter Interface

**Description:** Define rate limiter interface in `ratelimit/limiter.go`.

**Estimated Hours:** 1

**Acceptance Criteria:**
- [x] `Limiter` interface with `Allow()` and `Reset()` methods
- [x] Rate limit result struct
- [x] Key extraction helpers

**Implementation:**
```go
type Limiter interface {
    Allow(ctx context.Context, key string, rule Rule) (*Result, error)
    Reset(ctx context.Context, key string) error
}

type Result struct {
    Allowed    bool
    Remaining  int
    ResetAt    time.Time
    RetryAfter time.Duration
}

type Rule struct {
    Requests int
    Window   time.Duration
}
```

---

### 7.2 Sliding Window Implementation

**Description:** Implement sliding window rate limiter in `ratelimit/sliding.go`.

**Estimated Hours:** 4

**Acceptance Criteria:**
- [x] Sliding window algorithm
- [x] Uses store for persistence
- [x] Accurate rate limiting
- [x] Returns remaining count

**Testing:**
- [x] Unit test: Allows requests within limit
- [x] Unit test: Blocks requests over limit
- [x] Unit test: Window slides correctly
- [x] Unit test: Reset clears limit

---

### 7.3 Rate Limit Configuration

**Description:** Implement rate limit configuration in `ratelimit/config.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [x] Config struct for different endpoints
- [x] Key extraction strategies
- [x] Default rules

**Implementation:**
```go
type Config struct {
    Login    Rule
    Register Rule
    Refresh  Rule
    API      Rule
}

type KeyBy string

const (
    KeyByIP     KeyBy = "ip"
    KeyByEmail  KeyBy = "email"
    KeyByUserID KeyBy = "user_id"
    KeyByAPIKey KeyBy = "api_key"
)
```

---

### 7.4 Cleanup Worker

**Description:** Implement background cleanup in `cleanup/worker.go`.

**Estimated Hours:** 3

**Acceptance Criteria:**
- [x] Periodic cleanup of expired tokens
- [x] Configurable interval
- [x] Graceful shutdown
- [x] Logging of cleanup stats

**Implementation:**
```go
type Worker struct {
    store    Store
    interval time.Duration
    stop     chan struct{}
    done     chan struct{}
}

func New(store Store, interval time.Duration) *Worker
func (w *Worker) Start()
func (w *Worker) Stop()
```

**Testing:**
- [x] Unit test: Worker starts and stops
- [x] Unit test: Cleanup runs at interval
- [ ] Integration test: Expired tokens removed

---

## Remaining Work

> **STATUS: ~90% Complete** - Rate limiting and cleanup workers are implemented. Only need integration tests.

- [ ] Integration tests for cleanup with real stores

---

## Phase 7 Checklist

- [x] Rate limiter interface defined
- [x] Sliding window implemented
- [x] Rate limit config implemented
- [x] Cleanup worker implemented
- [x] All tests pass
