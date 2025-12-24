// Package cleanup provides background workers for cleaning up expired data.
package cleanup

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/aloks98/goauth/store"
)

// Worker performs periodic cleanup of expired data.
type Worker struct {
	store    store.Store
	interval time.Duration
	logger   Logger
	done     chan struct{}
	wg       sync.WaitGroup

	// Cleanup task toggles
	cleanRefreshTokens bool
	cleanBlacklist     bool
	cleanAPIKeys       bool

	// Stats
	mu                   sync.RWMutex
	lastRun              time.Time
	refreshTokensDeleted int64
	blacklistDeleted     int64
	apiKeysDeleted       int64
	errors               int64
}

// Logger is the interface for logging cleanup events.
type Logger interface {
	Printf(format string, v ...interface{})
}

// defaultLogger wraps the standard log package.
type defaultLogger struct{}

func (d *defaultLogger) Printf(format string, v ...interface{}) {
	log.Printf("[cleanup] "+format, v...)
}

// Config holds cleanup worker configuration.
type Config struct {
	// Store is the data store to clean up.
	Store store.Store

	// Interval is how often to run cleanup.
	// Defaults to 1 hour.
	Interval time.Duration

	// Logger for cleanup events.
	// Defaults to standard log package.
	Logger Logger

	// CleanRefreshTokens enables refresh token cleanup.
	// Defaults to true.
	CleanRefreshTokens *bool

	// CleanBlacklist enables blacklist cleanup.
	// Defaults to true.
	CleanBlacklist *bool

	// CleanAPIKeys enables API key cleanup.
	// Defaults to true.
	CleanAPIKeys *bool
}

// DefaultConfig returns a default cleanup configuration.
func DefaultConfig(s store.Store) *Config {
	t := true
	return &Config{
		Store:              s,
		Interval:           time.Hour,
		Logger:             &defaultLogger{},
		CleanRefreshTokens: &t,
		CleanBlacklist:     &t,
		CleanAPIKeys:       &t,
	}
}

// NewWorker creates a new cleanup worker.
func NewWorker(cfg *Config) *Worker {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}

	if cfg.Logger == nil {
		cfg.Logger = &defaultLogger{}
	}

	cleanRefresh := true
	if cfg.CleanRefreshTokens != nil {
		cleanRefresh = *cfg.CleanRefreshTokens
	}

	cleanBlacklist := true
	if cfg.CleanBlacklist != nil {
		cleanBlacklist = *cfg.CleanBlacklist
	}

	cleanAPIKeys := true
	if cfg.CleanAPIKeys != nil {
		cleanAPIKeys = *cfg.CleanAPIKeys
	}

	return &Worker{
		store:              cfg.Store,
		interval:           cfg.Interval,
		logger:             cfg.Logger,
		done:               make(chan struct{}),
		cleanRefreshTokens: cleanRefresh,
		cleanBlacklist:     cleanBlacklist,
		cleanAPIKeys:       cleanAPIKeys,
	}
}

// Start begins the cleanup worker.
func (w *Worker) Start() {
	w.wg.Add(1)
	go w.run()
}

// Stop gracefully stops the cleanup worker.
func (w *Worker) Stop() {
	close(w.done)
	w.wg.Wait()
}

// run is the main loop for the cleanup worker.
func (w *Worker) run() {
	defer w.wg.Done()

	// Run immediately on start
	w.runCleanup()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.runCleanup()
		}
	}
}

// runCleanup executes all enabled cleanup tasks.
func (w *Worker) runCleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	w.mu.Lock()
	w.lastRun = time.Now()
	w.mu.Unlock()

	var refreshDeleted, blacklistDeleted, apiKeysDeleted int64
	var errs int64

	// Clean refresh tokens
	if w.cleanRefreshTokens {
		count, err := w.store.DeleteExpiredRefreshTokens(ctx)
		if err != nil {
			w.logger.Printf("error cleaning refresh tokens: %v", err)
			errs++
		} else if count > 0 {
			refreshDeleted = count
			w.logger.Printf("deleted %d expired refresh tokens", count)
		}
	}

	// Clean blacklist entries
	if w.cleanBlacklist {
		count, err := w.store.DeleteExpiredBlacklistEntries(ctx)
		if err != nil {
			w.logger.Printf("error cleaning blacklist entries: %v", err)
			errs++
		} else if count > 0 {
			blacklistDeleted = count
			w.logger.Printf("deleted %d expired blacklist entries", count)
		}
	}

	// Clean API keys
	if w.cleanAPIKeys {
		count, err := w.store.DeleteExpiredAPIKeys(ctx)
		if err != nil {
			w.logger.Printf("error cleaning API keys: %v", err)
			errs++
		} else if count > 0 {
			apiKeysDeleted = count
			w.logger.Printf("deleted %d expired API keys", count)
		}
	}

	// Update stats
	w.mu.Lock()
	w.refreshTokensDeleted += refreshDeleted
	w.blacklistDeleted += blacklistDeleted
	w.apiKeysDeleted += apiKeysDeleted
	w.errors += errs
	w.mu.Unlock()
}

// RunNow triggers an immediate cleanup run.
func (w *Worker) RunNow() {
	w.runCleanup()
}

// Stats returns cleanup statistics.
type Stats struct {
	LastRun              time.Time
	RefreshTokensDeleted int64
	BlacklistDeleted     int64
	APIKeysDeleted       int64
	Errors               int64
}

// Stats returns the current cleanup statistics.
func (w *Worker) Stats() Stats {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return Stats{
		LastRun:              w.lastRun,
		RefreshTokensDeleted: w.refreshTokensDeleted,
		BlacklistDeleted:     w.blacklistDeleted,
		APIKeysDeleted:       w.apiKeysDeleted,
		Errors:               w.errors,
	}
}

// MultiWorker manages multiple cleanup workers with different intervals.
type MultiWorker struct {
	workers []*Worker
}

// NewMultiWorker creates a manager for multiple cleanup workers.
func NewMultiWorker(workers ...*Worker) *MultiWorker {
	return &MultiWorker{
		workers: workers,
	}
}

// Start begins all managed workers.
func (m *MultiWorker) Start() {
	for _, w := range m.workers {
		w.Start()
	}
}

// Stop gracefully stops all managed workers.
func (m *MultiWorker) Stop() {
	for _, w := range m.workers {
		w.Stop()
	}
}

// ScheduledTask represents a cleanup task that runs on a schedule.
type ScheduledTask struct {
	name     string
	task     func(context.Context) error
	interval time.Duration
	logger   Logger
	done     chan struct{}
	wg       sync.WaitGroup
}

// NewScheduledTask creates a new scheduled cleanup task.
func NewScheduledTask(name string, interval time.Duration, task func(context.Context) error, logger Logger) *ScheduledTask {
	if logger == nil {
		logger = &defaultLogger{}
	}
	return &ScheduledTask{
		name:     name,
		task:     task,
		interval: interval,
		logger:   logger,
		done:     make(chan struct{}),
	}
}

// Start begins the scheduled task.
func (s *ScheduledTask) Start() {
	s.wg.Add(1)
	go s.run()
}

// Stop gracefully stops the scheduled task.
func (s *ScheduledTask) Stop() {
	close(s.done)
	s.wg.Wait()
}

// run is the main loop for the scheduled task.
func (s *ScheduledTask) run() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			if err := s.task(ctx); err != nil {
				s.logger.Printf("[%s] error: %v", s.name, err)
			}
			cancel()
		}
	}
}

// Func is a function that performs cleanup and returns the number of items deleted.
type Func func(ctx context.Context) (int64, error)

// WrapFunc wraps a cleanup function with logging.
func WrapFunc(name string, fn Func, logger Logger) func(context.Context) error {
	if logger == nil {
		logger = &defaultLogger{}
	}
	return func(ctx context.Context) error {
		count, err := fn(ctx)
		if err != nil {
			return err
		}
		if count > 0 {
			logger.Printf("[%s] deleted %d items", name, count)
		}
		return nil
	}
}
