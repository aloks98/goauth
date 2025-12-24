package sql

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/aloks98/goauth/store"
)

// Store implements store.Store using a SQL database.
type Store struct {
	db      *sql.DB
	dialect Dialect
	queries *dialectQueries
}

// Config holds SQL store configuration.
type Config struct {
	// Dialect specifies the database type (postgres, mysql).
	Dialect Dialect

	// DB is an existing database connection.
	// If provided, DSN is ignored.
	DB *sql.DB

	// DSN is the data source name for connecting to the database.
	DSN string

	// TablePrefix is the prefix for all table names.
	// Defaults to "goauth_" if empty.
	// Example: "myapp_" creates tables like "myapp_refresh_tokens".
	TablePrefix string

	// MaxOpenConns sets the maximum number of open connections.
	MaxOpenConns int

	// MaxIdleConns sets the maximum number of idle connections.
	MaxIdleConns int

	// ConnMaxLifetime sets the maximum lifetime of a connection.
	ConnMaxLifetime time.Duration
}

// New creates a new SQL store.
func New(cfg *Config) (*Store, error) {
	var db *sql.DB
	var err error

	if cfg.DB != nil {
		db = cfg.DB
	} else {
		driverName := getDriverName(cfg.Dialect)
		db, err = sql.Open(driverName, cfg.DSN)
		if err != nil {
			return nil, err
		}

		if cfg.MaxOpenConns > 0 {
			db.SetMaxOpenConns(cfg.MaxOpenConns)
		}
		if cfg.MaxIdleConns > 0 {
			db.SetMaxIdleConns(cfg.MaxIdleConns)
		}
		if cfg.ConnMaxLifetime > 0 {
			db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
		}
	}

	tablePrefix := cfg.TablePrefix
	if tablePrefix == "" {
		tablePrefix = "goauth_"
	}

	return &Store{
		db:      db,
		dialect: cfg.Dialect,
		queries: getDialectQueries(cfg.Dialect, tablePrefix),
	}, nil
}

// getDriverName returns the driver name for the dialect.
func getDriverName(d Dialect) string {
	switch d {
	case MySQL:
		return "mysql"
	default:
		return "pgx"
	}
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping verifies the database connection is alive.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Migrate creates the database schema.
func (s *Store) Migrate(ctx context.Context) error {
	// Split schema by semicolon for multiple statements
	statements := strings.Split(s.queries.schema, ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}

	return nil
}

// SaveRefreshToken persists a refresh token.
func (s *Store) SaveRefreshToken(ctx context.Context, token *store.RefreshToken) error {
	_, err := s.db.ExecContext(ctx, s.queries.insertRefreshToken,
		token.ID,
		token.UserID,
		token.FamilyID,
		token.TokenHash,
		token.IssuedAt,
		token.ExpiresAt,
	)
	return err
}

// GetRefreshToken retrieves a refresh token by JTI.
func (s *Store) GetRefreshToken(ctx context.Context, jti string) (*store.RefreshToken, error) {
	token := &store.RefreshToken{}
	var revokedAt sql.NullTime
	var replacedBy sql.NullString

	err := s.db.QueryRowContext(ctx, s.queries.selectRefreshToken, jti).Scan(
		&token.ID,
		&token.UserID,
		&token.FamilyID,
		&token.TokenHash,
		&token.IssuedAt,
		&token.ExpiresAt,
		&revokedAt,
		&replacedBy,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}
	if replacedBy.Valid {
		token.ReplacedBy = &replacedBy.String
	}

	return token, nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (s *Store) RevokeRefreshToken(ctx context.Context, jti string, replacedBy string) error {
	var err error
	if s.dialect == MySQL {
		// MySQL uses ? placeholders with different parameter order
		_, err = s.db.ExecContext(ctx, s.queries.revokeRefreshToken, replacedBy, jti)
	} else {
		_, err = s.db.ExecContext(ctx, s.queries.revokeRefreshToken, jti, replacedBy)
	}
	return err
}

// RevokeTokenFamily revokes all tokens in a family.
func (s *Store) RevokeTokenFamily(ctx context.Context, familyID string) error {
	_, err := s.db.ExecContext(ctx, s.queries.revokeTokenFamily, familyID)
	return err
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user.
func (s *Store) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, s.queries.revokeAllUserRefreshTokens, userID)
	return err
}

// DeleteExpiredRefreshTokens removes expired refresh tokens.
func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, s.queries.deleteExpiredRefreshTokens)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// AddToBlacklist adds an access token JTI to the blacklist.
func (s *Store) AddToBlacklist(ctx context.Context, jti string, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx, s.queries.insertBlacklist, jti, expiresAt)
	return err
}

// IsBlacklisted checks if an access token JTI is blacklisted.
func (s *Store) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, s.queries.selectBlacklist, jti).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// DeleteExpiredBlacklistEntries removes expired blacklist entries.
func (s *Store) DeleteExpiredBlacklistEntries(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, s.queries.deleteExpiredBlacklistEntries, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetUserPermissions retrieves user permissions.
func (s *Store) GetUserPermissions(ctx context.Context, userID string) (*store.UserPermissions, error) {
	perms := &store.UserPermissions{}
	var permissionsJSON string
	var baseRole sql.NullString

	err := s.db.QueryRowContext(ctx, s.queries.selectUserPermissions, userID).Scan(
		&perms.UserID,
		&perms.RoleLabel,
		&baseRole,
		&permissionsJSON,
		&perms.PermissionVersion,
		&perms.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if baseRole.Valid {
		perms.BaseRole = baseRole.String
	}

	if err := json.Unmarshal([]byte(permissionsJSON), &perms.Permissions); err != nil {
		return nil, err
	}

	return perms, nil
}

// SaveUserPermissions creates or updates user permissions.
func (s *Store) SaveUserPermissions(ctx context.Context, perms *store.UserPermissions) error {
	permissionsJSON, err := json.Marshal(perms.Permissions)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, s.queries.upsertUserPermissions,
		perms.UserID,
		perms.RoleLabel,
		nullString(perms.BaseRole),
		string(permissionsJSON),
		perms.PermissionVersion,
		perms.UpdatedAt,
	)
	return err
}

// DeleteUserPermissions removes user permissions.
func (s *Store) DeleteUserPermissions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, s.queries.deleteUserPermissions, userID)
	return err
}

// UpdateUsersWithRole updates all users with a specific role.
func (s *Store) UpdateUsersWithRole(ctx context.Context, roleLabel string, permissions []string, newVersion int) (int64, error) {
	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		return 0, err
	}

	var result sql.Result
	if s.dialect == MySQL {
		// MySQL uses ? placeholders with different parameter order
		result, err = s.db.ExecContext(ctx, s.queries.updateUsersWithRole, string(permissionsJSON), newVersion, roleLabel)
	} else {
		result, err = s.db.ExecContext(ctx, s.queries.updateUsersWithRole, roleLabel, string(permissionsJSON), newVersion)
	}
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetRoleTemplates retrieves all role templates.
func (s *Store) GetRoleTemplates(ctx context.Context) (map[string]*store.StoredRoleTemplate, error) {
	rows, err := s.db.QueryContext(ctx, s.queries.selectRoleTemplates)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	templates := make(map[string]*store.StoredRoleTemplate)
	for rows.Next() {
		t := &store.StoredRoleTemplate{}
		var permissionsJSON string

		if err := rows.Scan(&t.Key, &permissionsJSON, &t.PermissionHash, &t.Version, &t.UpdatedAt); err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(permissionsJSON), &t.Permissions); err != nil {
			return nil, err
		}

		templates[t.Key] = t
	}

	return templates, rows.Err()
}

// SaveRoleTemplate saves a role template.
func (s *Store) SaveRoleTemplate(ctx context.Context, template *store.StoredRoleTemplate) error {
	permissionsJSON, err := json.Marshal(template.Permissions)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, s.queries.upsertRoleTemplate,
		template.Key,
		string(permissionsJSON),
		template.PermissionHash,
		template.Version,
		template.UpdatedAt,
	)
	return err
}

// SaveAPIKey saves an API key.
func (s *Store) SaveAPIKey(ctx context.Context, key *store.APIKey) error {
	var scopesJSON *string
	if len(key.Scopes) > 0 {
		b, err := json.Marshal(key.Scopes)
		if err != nil {
			return err
		}
		s := string(b)
		scopesJSON = &s
	}

	_, err := s.db.ExecContext(ctx, s.queries.insertAPIKey,
		key.ID,
		key.UserID,
		nullString(key.Name),
		key.Prefix,
		key.KeyHash,
		nullString(key.Hint),
		scopesJSON,
		key.CreatedAt,
		key.ExpiresAt,
	)
	return err
}

// GetAPIKeyByHash retrieves an API key by prefix and hash.
func (s *Store) GetAPIKeyByHash(ctx context.Context, prefix, keyHash string) (*store.APIKey, error) {
	key := &store.APIKey{}
	var name, hint, scopesJSON sql.NullString
	var expiresAt, lastUsedAt, revokedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, s.queries.selectAPIKeyByHash, prefix, keyHash).Scan(
		&key.ID,
		&key.UserID,
		&name,
		&key.Prefix,
		&key.KeyHash,
		&hint,
		&scopesJSON,
		&key.CreatedAt,
		&expiresAt,
		&lastUsedAt,
		&revokedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if name.Valid {
		key.Name = name.String
	}
	if hint.Valid {
		key.Hint = hint.String
	}
	if scopesJSON.Valid {
		if err := json.Unmarshal([]byte(scopesJSON.String), &key.Scopes); err != nil {
			return nil, err
		}
	}
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	if revokedAt.Valid {
		key.RevokedAt = &revokedAt.Time
	}

	return key, nil
}

// GetAPIKeysByUser retrieves all API keys for a user.
func (s *Store) GetAPIKeysByUser(ctx context.Context, userID string) ([]*store.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, s.queries.selectAPIKeysByUser, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var keys []*store.APIKey
	for rows.Next() {
		key := &store.APIKey{}
		var name, hint, scopesJSON sql.NullString
		var expiresAt, lastUsedAt, revokedAt sql.NullTime

		if err := rows.Scan(
			&key.ID,
			&key.UserID,
			&name,
			&key.Prefix,
			&key.KeyHash,
			&hint,
			&scopesJSON,
			&key.CreatedAt,
			&expiresAt,
			&lastUsedAt,
			&revokedAt,
		); err != nil {
			return nil, err
		}

		if name.Valid {
			key.Name = name.String
		}
		if hint.Valid {
			key.Hint = hint.String
		}
		if scopesJSON.Valid {
			if err := json.Unmarshal([]byte(scopesJSON.String), &key.Scopes); err != nil {
				return nil, err
			}
		}
		if expiresAt.Valid {
			key.ExpiresAt = &expiresAt.Time
		}
		if lastUsedAt.Valid {
			key.LastUsedAt = &lastUsedAt.Time
		}
		if revokedAt.Valid {
			key.RevokedAt = &revokedAt.Time
		}

		keys = append(keys, key)
	}

	return keys, rows.Err()
}

// RevokeAPIKey revokes an API key.
func (s *Store) RevokeAPIKey(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.queries.revokeAPIKey, id)
	return err
}

// DeleteExpiredAPIKeys removes expired API keys.
func (s *Store) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, s.queries.deleteExpiredAPIKeys)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// nullString converts a string to sql.NullString.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// Ensure Store implements store.Store.
var _ store.Store = (*Store)(nil)
