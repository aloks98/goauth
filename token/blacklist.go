package token

import (
	"context"
	"time"
)

// AddToBlacklist adds an access token JTI to the blacklist.
func (s *Service) AddToBlacklist(ctx context.Context, jti string, expiresAt time.Time) error {
	return s.store.AddToBlacklist(ctx, jti, expiresAt.Unix())
}

// IsBlacklisted checks if an access token JTI is blacklisted.
func (s *Service) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	return s.store.IsBlacklisted(ctx, jti)
}
