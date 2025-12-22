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
- [ ] `Limiter` interface with `Allow()` and `Reset()` methods
- [ ] Rate limit result struct
- [ ] Key extraction helpers

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
- [ ] Sliding window algorithm
- [ ] Uses store for persistence
- [ ] Accurate rate limiting
- [ ] Returns remaining count

**Testing:**
- [ ] Unit test: Allows requests within limit
- [ ] Unit test: Blocks requests over limit
- [ ] Unit test: Window slides correctly
- [ ] Unit test: Reset clears limit

---

### 7.3 Rate Limit Configuration

**Description:** Implement rate limit configuration in `ratelimit/config.go`.

**Estimated Hours:** 2

**Acceptance Criteria:**
- [ ] Config struct for different endpoints
- [ ] Key extraction strategies
- [ ] Default rules

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
- [ ] Periodic cleanup of expired tokens
- [ ] Configurable interval
- [ ] Graceful shutdown
- [ ] Logging of cleanup stats

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
- [ ] Unit test: Worker starts and stops
- [ ] Unit test: Cleanup runs at interval
- [ ] Integration test: Expired tokens removed

---

## Phase 7 Checklist

- [ ] Rate limiter interface defined
- [ ] Sliding window implemented
- [ ] Rate limit config implemented
- [ ] Cleanup worker implemented
- [ ] All tests pass
