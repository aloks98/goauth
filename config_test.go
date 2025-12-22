package goauth

import (
	"errors"
	"testing"
	"time"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	if cfg.AccessTokenTTL != DefaultAccessTokenTTL {
		t.Errorf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, DefaultAccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != DefaultRefreshTokenTTL {
		t.Errorf("RefreshTokenTTL = %v, want %v", cfg.RefreshTokenTTL, DefaultRefreshTokenTTL)
	}
	if cfg.SigningMethod != SigningMethodHS256 {
		t.Errorf("SigningMethod = %v, want %v", cfg.SigningMethod, SigningMethodHS256)
	}
	if cfg.TablePrefix != DefaultTablePrefix {
		t.Errorf("TablePrefix = %q, want %q", cfg.TablePrefix, DefaultTablePrefix)
	}
	if cfg.APIKeyPrefix != DefaultAPIKeyPrefix {
		t.Errorf("APIKeyPrefix = %q, want %q", cfg.APIKeyPrefix, DefaultAPIKeyPrefix)
	}
	if cfg.APIKeyLength != DefaultAPIKeyLength {
		t.Errorf("APIKeyLength = %d, want %d", cfg.APIKeyLength, DefaultAPIKeyLength)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr error
	}{
		{
			name:    "valid config",
			modify:  func(c *Config) { c.Secret = "this-is-a-32-character-secret!!!" },
			wantErr: nil,
		},
		{
			name:    "missing secret",
			modify:  func(c *Config) {},
			wantErr: ErrConfigInvalid,
		},
		{
			name:    "secret too short",
			modify:  func(c *Config) { c.Secret = "short" },
			wantErr: ErrConfigInvalid,
		},
		{
			name: "RS256 without private key",
			modify: func(c *Config) {
				c.SigningMethod = SigningMethodRS256
				c.PublicKey = "dummy"
			},
			wantErr: ErrConfigInvalid,
		},
		{
			name: "RS256 without public key",
			modify: func(c *Config) {
				c.SigningMethod = SigningMethodRS256
				c.PrivateKey = "dummy"
			},
			wantErr: ErrConfigInvalid,
		},
		{
			name: "invalid signing method",
			modify: func(c *Config) {
				c.Secret = "this-is-a-32-character-secret!!!"
				c.SigningMethod = "INVALID"
			},
			wantErr: ErrConfigInvalid,
		},
		{
			name: "zero access token TTL",
			modify: func(c *Config) {
				c.Secret = "this-is-a-32-character-secret!!!"
				c.AccessTokenTTL = 0
			},
			wantErr: ErrConfigInvalid,
		},
		{
			name: "zero refresh token TTL",
			modify: func(c *Config) {
				c.Secret = "this-is-a-32-character-secret!!!"
				c.RefreshTokenTTL = 0
			},
			wantErr: ErrConfigInvalid,
		},
		{
			name: "refresh TTL less than access TTL",
			modify: func(c *Config) {
				c.Secret = "this-is-a-32-character-secret!!!"
				c.AccessTokenTTL = time.Hour
				c.RefreshTokenTTL = time.Minute
			},
			wantErr: ErrConfigInvalid,
		},
		{
			name: "API key length too short",
			modify: func(c *Config) {
				c.Secret = "this-is-a-32-character-secret!!!"
				c.APIKeyLength = 8
			},
			wantErr: ErrConfigInvalid,
		},
		{
			name: "empty API key prefix",
			modify: func(c *Config) {
				c.Secret = "this-is-a-32-character-secret!!!"
				c.APIKeyPrefix = ""
			},
			wantErr: ErrConfigInvalid,
		},
		{
			name: "negative cleanup interval",
			modify: func(c *Config) {
				c.Secret = "this-is-a-32-character-secret!!!"
				c.CleanupInterval = -time.Hour
			},
			wantErr: ErrConfigInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			tt.modify(cfg)
			err := cfg.Validate()

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_IsRBACEnabled(t *testing.T) {
	tests := []struct {
		name     string
		modify   func(*Config)
		expected bool
	}{
		{
			name:     "no RBAC config",
			modify:   func(c *Config) {},
			expected: false,
		},
		{
			name:     "with RBAC config",
			modify:   func(c *Config) { c.RBACConfig = &RBACConfig{Version: 1} },
			expected: true,
		},
		{
			name:     "with RBAC config path",
			modify:   func(c *Config) { c.RBACConfigPath = "./permissions.yaml" },
			expected: true,
		},
		{
			name:     "with RBAC config data",
			modify:   func(c *Config) { c.RBACConfigData = []byte("version: 1") },
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			tt.modify(cfg)
			if got := cfg.IsRBACEnabled(); got != tt.expected {
				t.Errorf("IsRBACEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_IsHMAC(t *testing.T) {
	tests := []struct {
		method   SigningMethod
		expected bool
	}{
		{SigningMethodHS256, true},
		{SigningMethodHS384, true},
		{SigningMethodHS512, true},
		{SigningMethodRS256, false},
		{SigningMethodRS384, false},
		{SigningMethodRS512, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			cfg := &Config{SigningMethod: tt.method}
			if got := cfg.IsHMAC(); got != tt.expected {
				t.Errorf("IsHMAC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_IsRSA(t *testing.T) {
	tests := []struct {
		method   SigningMethod
		expected bool
	}{
		{SigningMethodRS256, true},
		{SigningMethodRS384, true},
		{SigningMethodRS512, true},
		{SigningMethodHS256, false},
		{SigningMethodHS384, false},
		{SigningMethodHS512, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			cfg := &Config{SigningMethod: tt.method}
			if got := cfg.IsRSA(); got != tt.expected {
				t.Errorf("IsRSA() = %v, want %v", got, tt.expected)
			}
		})
	}
}
