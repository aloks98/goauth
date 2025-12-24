package cleanup

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aloks98/goauth/store"
)

// mockStore implements store.Store for testing
type mockStore struct {
	refreshTokensDeleted int64
	blacklistDeleted     int64
	apiKeysDeleted       int64
	errorOnRefresh       bool
	errorOnBlacklist     bool
	errorOnAPIKeys       bool
}

func (m *mockStore) Close() error                      { return nil }
func (m *mockStore) Ping(ctx context.Context) error    { return nil }
func (m *mockStore) Migrate(ctx context.Context) error { return nil }

func (m *mockStore) SaveRefreshToken(ctx context.Context, token *store.RefreshToken) error {
	return nil
}

func (m *mockStore) GetRefreshToken(ctx context.Context, jti string) (*store.RefreshToken, error) {
	return nil, nil
}

func (m *mockStore) RevokeRefreshToken(ctx context.Context, jti string, replacedBy string) error {
	return nil
}

func (m *mockStore) RevokeTokenFamily(ctx context.Context, familyID string) error {
	return nil
}

func (m *mockStore) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	return nil
}

func (m *mockStore) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	if m.errorOnRefresh {
		return 0, errors.New("refresh token error")
	}
	return atomic.AddInt64(&m.refreshTokensDeleted, 5), nil
}

func (m *mockStore) AddToBlacklist(ctx context.Context, jti string, expiresAt int64) error {
	return nil
}

func (m *mockStore) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	return false, nil
}

func (m *mockStore) DeleteExpiredBlacklistEntries(ctx context.Context) (int64, error) {
	if m.errorOnBlacklist {
		return 0, errors.New("blacklist error")
	}
	return atomic.AddInt64(&m.blacklistDeleted, 3), nil
}

func (m *mockStore) GetUserPermissions(ctx context.Context, userID string) (*store.UserPermissions, error) {
	return nil, nil
}

func (m *mockStore) SaveUserPermissions(ctx context.Context, perms *store.UserPermissions) error {
	return nil
}

func (m *mockStore) DeleteUserPermissions(ctx context.Context, userID string) error {
	return nil
}

func (m *mockStore) UpdateUsersWithRole(ctx context.Context, roleLabel string, permissions []string, newVersion int) (int64, error) {
	return 0, nil
}

func (m *mockStore) GetRoleTemplates(ctx context.Context) (map[string]*store.StoredRoleTemplate, error) {
	return nil, nil
}

func (m *mockStore) SaveRoleTemplate(ctx context.Context, template *store.StoredRoleTemplate) error {
	return nil
}

func (m *mockStore) SaveAPIKey(ctx context.Context, key *store.APIKey) error {
	return nil
}

func (m *mockStore) GetAPIKeyByHash(ctx context.Context, prefix string, keyHash string) (*store.APIKey, error) {
	return nil, nil
}

func (m *mockStore) GetAPIKeysByUser(ctx context.Context, userID string) ([]*store.APIKey, error) {
	return nil, nil
}

func (m *mockStore) RevokeAPIKey(ctx context.Context, id string) error {
	return nil
}

func (m *mockStore) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	if m.errorOnAPIKeys {
		return 0, errors.New("api keys error")
	}
	return atomic.AddInt64(&m.apiKeysDeleted, 2), nil
}

// testLogger captures log messages for testing
type testLogger struct {
	messages []string
}

func (l *testLogger) Printf(format string, v ...interface{}) {
	// Just count calls, don't actually format
	l.messages = append(l.messages, format)
}

func TestWorker_RunCleanup(t *testing.T) {
	ms := &mockStore{}
	logger := &testLogger{}

	cfg := &Config{
		Store:    ms,
		Interval: time.Hour,
		Logger:   logger,
	}

	worker := NewWorker(cfg)

	// Run cleanup directly
	worker.runCleanup()

	// Check stats
	stats := worker.Stats()
	if stats.RefreshTokensDeleted != 5 {
		t.Errorf("expected 5 refresh tokens deleted, got %d", stats.RefreshTokensDeleted)
	}
	if stats.BlacklistDeleted != 3 {
		t.Errorf("expected 3 blacklist entries deleted, got %d", stats.BlacklistDeleted)
	}
	if stats.APIKeysDeleted != 2 {
		t.Errorf("expected 2 API keys deleted, got %d", stats.APIKeysDeleted)
	}
	if stats.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", stats.Errors)
	}
	if stats.LastRun.IsZero() {
		t.Error("expected LastRun to be set")
	}
}

func TestWorker_RunCleanup_WithErrors(t *testing.T) {
	ms := &mockStore{
		errorOnRefresh:   true,
		errorOnBlacklist: true,
		errorOnAPIKeys:   true,
	}
	logger := &testLogger{}

	cfg := &Config{
		Store:    ms,
		Interval: time.Hour,
		Logger:   logger,
	}

	worker := NewWorker(cfg)
	worker.runCleanup()

	stats := worker.Stats()
	if stats.Errors != 3 {
		t.Errorf("expected 3 errors, got %d", stats.Errors)
	}
}

func TestWorker_DisabledTasks(t *testing.T) {
	ms := &mockStore{}
	logger := &testLogger{}

	f := false
	cfg := &Config{
		Store:              ms,
		Interval:           time.Hour,
		Logger:             logger,
		CleanRefreshTokens: &f,
		CleanBlacklist:     &f,
		CleanAPIKeys:       &f,
	}

	worker := NewWorker(cfg)
	worker.runCleanup()

	stats := worker.Stats()
	if stats.RefreshTokensDeleted != 0 {
		t.Error("refresh tokens should not be cleaned when disabled")
	}
	if stats.BlacklistDeleted != 0 {
		t.Error("blacklist should not be cleaned when disabled")
	}
	if stats.APIKeysDeleted != 0 {
		t.Error("API keys should not be cleaned when disabled")
	}
}

func TestWorker_StartStop(t *testing.T) {
	ms := &mockStore{}
	logger := &testLogger{}

	cfg := &Config{
		Store:    ms,
		Interval: 50 * time.Millisecond,
		Logger:   logger,
	}

	worker := NewWorker(cfg)
	worker.Start()

	// Wait for a few cleanup cycles
	time.Sleep(150 * time.Millisecond)

	worker.Stop()

	stats := worker.Stats()
	// Should have run at least 2-3 times (immediately + 2 intervals)
	if stats.RefreshTokensDeleted < 10 {
		t.Errorf("expected multiple cleanup runs, got refresh tokens deleted: %d", stats.RefreshTokensDeleted)
	}
}

func TestWorker_RunNow(t *testing.T) {
	ms := &mockStore{}
	logger := &testLogger{}

	cfg := &Config{
		Store:    ms,
		Interval: time.Hour,
		Logger:   logger,
	}

	worker := NewWorker(cfg)

	// Run cleanup manually
	worker.RunNow()

	stats := worker.Stats()
	if stats.RefreshTokensDeleted != 5 {
		t.Errorf("expected 5 refresh tokens deleted, got %d", stats.RefreshTokensDeleted)
	}
}

func TestMultiWorker(t *testing.T) {
	ms1 := &mockStore{}
	ms2 := &mockStore{}

	cfg1 := &Config{Store: ms1, Interval: 50 * time.Millisecond}
	cfg2 := &Config{Store: ms2, Interval: 50 * time.Millisecond}

	w1 := NewWorker(cfg1)
	w2 := NewWorker(cfg2)

	multi := NewMultiWorker(w1, w2)
	multi.Start()

	time.Sleep(150 * time.Millisecond)

	multi.Stop()

	// Both workers should have run
	if w1.Stats().RefreshTokensDeleted == 0 {
		t.Error("worker1 should have run")
	}
	if w2.Stats().RefreshTokensDeleted == 0 {
		t.Error("worker2 should have run")
	}
}

func TestScheduledTask(t *testing.T) {
	var runCount int32

	task := NewScheduledTask("test", 50*time.Millisecond, func(ctx context.Context) error {
		atomic.AddInt32(&runCount, 1)
		return nil
	}, nil)

	task.Start()
	time.Sleep(150 * time.Millisecond)
	task.Stop()

	// Should have run 2-3 times
	count := atomic.LoadInt32(&runCount)
	if count < 2 {
		t.Errorf("expected at least 2 runs, got %d", count)
	}
}

func TestScheduledTask_WithError(t *testing.T) {
	logger := &testLogger{}

	task := NewScheduledTask("error-task", 50*time.Millisecond, func(ctx context.Context) error {
		return errors.New("test error")
	}, logger)

	task.Start()
	time.Sleep(100 * time.Millisecond)
	task.Stop()

	// Logger should have received error messages
	if len(logger.messages) == 0 {
		t.Error("expected error to be logged")
	}
}

func TestWrapFunc(t *testing.T) {
	logger := &testLogger{}

	fn := func(ctx context.Context) (int64, error) {
		return 10, nil
	}

	wrapped := WrapFunc("test", fn, logger)

	err := wrapped(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(logger.messages) != 1 {
		t.Errorf("expected 1 log message, got %d", len(logger.messages))
	}
}

func TestWrapFunc_ZeroDeleted(t *testing.T) {
	logger := &testLogger{}

	fn := func(ctx context.Context) (int64, error) {
		return 0, nil
	}

	wrapped := WrapFunc("test", fn, logger)

	err := wrapped(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should not log when nothing deleted
	if len(logger.messages) != 0 {
		t.Errorf("expected no log messages for zero deletions, got %d", len(logger.messages))
	}
}

func TestWrapFunc_Error(t *testing.T) {
	logger := &testLogger{}

	fn := func(ctx context.Context) (int64, error) {
		return 0, errors.New("test error")
	}

	wrapped := WrapFunc("test", fn, logger)

	err := wrapped(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

func TestDefaultConfig_Values(t *testing.T) {
	ms := &mockStore{}
	cfg := DefaultConfig(ms)

	if cfg.Store != ms {
		t.Error("store not set correctly")
	}
	if cfg.Interval != time.Hour {
		t.Errorf("expected interval 1h, got %v", cfg.Interval)
	}
	if cfg.Logger == nil {
		t.Error("logger should be set")
	}
	if cfg.CleanRefreshTokens == nil || !*cfg.CleanRefreshTokens {
		t.Error("CleanRefreshTokens should default to true")
	}
	if cfg.CleanBlacklist == nil || !*cfg.CleanBlacklist {
		t.Error("CleanBlacklist should default to true")
	}
	if cfg.CleanAPIKeys == nil || !*cfg.CleanAPIKeys {
		t.Error("CleanAPIKeys should default to true")
	}
}
