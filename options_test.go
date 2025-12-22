package goauth

import (
	"os"
	"testing"
	"time"
)

func TestWithSecret(t *testing.T) {
	cfg := NewConfig()
	WithSecret("my-secret-key")(cfg)

	if cfg.Secret != "my-secret-key" {
		t.Errorf("Secret = %q, want %q", cfg.Secret, "my-secret-key")
	}
}

func TestWithRBACFromFile(t *testing.T) {
	cfg := NewConfig()
	WithRBACFromFile("./permissions.yaml")(cfg)

	if cfg.RBACConfigPath != "./permissions.yaml" {
		t.Errorf("RBACConfigPath = %q, want %q", cfg.RBACConfigPath, "./permissions.yaml")
	}
}

func TestWithRBACFromBytes(t *testing.T) {
	cfg := NewConfig()
	data := []byte("version: 1")
	WithRBACFromBytes(data)(cfg)

	if string(cfg.RBACConfigData) != "version: 1" {
		t.Errorf("RBACConfigData = %q, want %q", cfg.RBACConfigData, "version: 1")
	}
}

func TestWithRBACFromEnv(t *testing.T) {
	// Set env var
	os.Setenv("GOAUTH_RBAC_CONFIG", "version: 2")
	defer os.Unsetenv("GOAUTH_RBAC_CONFIG")

	cfg := NewConfig()
	WithRBACFromEnv()(cfg)

	if string(cfg.RBACConfigData) != "version: 2" {
		t.Errorf("RBACConfigData = %q, want %q", cfg.RBACConfigData, "version: 2")
	}
}

func TestWithRBACFromEnv_NotSet(t *testing.T) {
	os.Unsetenv("GOAUTH_RBAC_CONFIG")

	cfg := NewConfig()
	WithRBACFromEnv()(cfg)

	if cfg.RBACConfigData != nil {
		t.Error("RBACConfigData should be nil when env not set")
	}
}

func TestWithAccessTokenTTL(t *testing.T) {
	cfg := NewConfig()
	WithAccessTokenTTL(30 * time.Minute)(cfg)

	if cfg.AccessTokenTTL != 30*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, 30*time.Minute)
	}
}

func TestWithRefreshTokenTTL(t *testing.T) {
	cfg := NewConfig()
	WithRefreshTokenTTL(24 * time.Hour)(cfg)

	if cfg.RefreshTokenTTL != 24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want %v", cfg.RefreshTokenTTL, 24*time.Hour)
	}
}

func TestWithSigningMethod(t *testing.T) {
	cfg := NewConfig()
	WithSigningMethod(SigningMethodRS256)(cfg)

	if cfg.SigningMethod != SigningMethodRS256 {
		t.Errorf("SigningMethod = %v, want %v", cfg.SigningMethod, SigningMethodRS256)
	}
}

func TestWithKeyPair(t *testing.T) {
	cfg := NewConfig()
	privateKey := "private-key"
	publicKey := "public-key"
	WithKeyPair(privateKey, publicKey)(cfg)

	if cfg.PrivateKey != privateKey {
		t.Errorf("PrivateKey = %v, want %v", cfg.PrivateKey, privateKey)
	}
	if cfg.PublicKey != publicKey {
		t.Errorf("PublicKey = %v, want %v", cfg.PublicKey, publicKey)
	}
}

func TestWithTablePrefix(t *testing.T) {
	cfg := NewConfig()
	WithTablePrefix("myapp_")(cfg)

	if cfg.TablePrefix != "myapp_" {
		t.Errorf("TablePrefix = %q, want %q", cfg.TablePrefix, "myapp_")
	}
}

func TestWithAutoMigrate(t *testing.T) {
	cfg := NewConfig()
	WithAutoMigrate(true)(cfg)

	if !cfg.AutoMigrate {
		t.Error("AutoMigrate should be true")
	}
}

func TestWithCleanupInterval(t *testing.T) {
	cfg := NewConfig()
	WithCleanupInterval(2 * time.Hour)(cfg)

	if cfg.CleanupInterval != 2*time.Hour {
		t.Errorf("CleanupInterval = %v, want %v", cfg.CleanupInterval, 2*time.Hour)
	}
}

func TestWithPermissionVersionCheck(t *testing.T) {
	cfg := NewConfig()
	WithPermissionVersionCheck(false)(cfg)

	if cfg.PermissionVersionCheck {
		t.Error("PermissionVersionCheck should be false")
	}
}

func TestWithPermissionCacheTTL(t *testing.T) {
	cfg := NewConfig()
	WithPermissionCacheTTL(time.Minute)(cfg)

	if cfg.PermissionCacheTTL != time.Minute {
		t.Errorf("PermissionCacheTTL = %v, want %v", cfg.PermissionCacheTTL, time.Minute)
	}
}

func TestWithRoleSyncOnStartup(t *testing.T) {
	cfg := NewConfig()
	WithRoleSyncOnStartup(false)(cfg)

	if cfg.RoleSyncOnStartup {
		t.Error("RoleSyncOnStartup should be false")
	}
}

func TestWithAPIKeyPrefix(t *testing.T) {
	cfg := NewConfig()
	WithAPIKeyPrefix("sk_live")(cfg)

	if cfg.APIKeyPrefix != "sk_live" {
		t.Errorf("APIKeyPrefix = %q, want %q", cfg.APIKeyPrefix, "sk_live")
	}
}

func TestWithAPIKeyLength(t *testing.T) {
	cfg := NewConfig()
	WithAPIKeyLength(64)(cfg)

	if cfg.APIKeyLength != 64 {
		t.Errorf("APIKeyLength = %d, want %d", cfg.APIKeyLength, 64)
	}
}

func TestOptionChaining(t *testing.T) {
	cfg := NewConfig()

	options := []Option{
		WithSecret("this-is-a-32-character-secret!!!"),
		WithAccessTokenTTL(30 * time.Minute),
		WithRefreshTokenTTL(14 * 24 * time.Hour),
		WithTablePrefix("test_"),
		WithAutoMigrate(true),
	}

	for _, opt := range options {
		opt(cfg)
	}

	if cfg.Secret != "this-is-a-32-character-secret!!!" {
		t.Error("Secret not set correctly")
	}
	if cfg.AccessTokenTTL != 30*time.Minute {
		t.Error("AccessTokenTTL not set correctly")
	}
	if cfg.RefreshTokenTTL != 14*24*time.Hour {
		t.Error("RefreshTokenTTL not set correctly")
	}
	if cfg.TablePrefix != "test_" {
		t.Error("TablePrefix not set correctly")
	}
	if !cfg.AutoMigrate {
		t.Error("AutoMigrate not set correctly")
	}
}
