// Package queries embeds SQL query files for the SQL store.
package queries

import (
	"embed"
	"strings"
)

// PostgresFS embeds PostgreSQL query files.
//
//go:embed postgres/*.sql
var PostgresFS embed.FS

// MySQLFS embeds MySQL query files.
//
//go:embed mysql/*.sql
var MySQLFS embed.FS

// Queries holds parsed SQL queries by name.
type Queries struct {
	Schema                 string
	InsertRefreshToken     string
	SelectRefreshToken     string
	RevokeRefreshToken     string
	RevokeTokenFamily      string
	RevokeAllUserTokens    string
	DeleteExpiredTokens    string
	InsertBlacklist        string
	SelectBlacklist        string
	DeleteExpiredBlacklist string
	SelectUserPerms        string
	UpsertUserPerms        string
	DeleteUserPerms        string
	UpdateUsersWithRole    string
	SelectRoleTemplates    string
	UpsertRoleTemplate     string
	InsertAPIKey           string
	SelectAPIKeyByHash     string
	SelectAPIKeysByUser    string
	RevokeAPIKey           string
	DeleteExpiredAPIKeys   string
}

// LoadPostgres loads PostgreSQL queries from embedded files.
func LoadPostgres() (*Queries, error) {
	return loadQueries(PostgresFS, "postgres")
}

// LoadMySQL loads MySQL queries from embedded files.
func LoadMySQL() (*Queries, error) {
	return loadQueries(MySQLFS, "mysql")
}

func loadQueries(fs embed.FS, dir string) (*Queries, error) {
	q := &Queries{}

	// Load schema
	schema, err := fs.ReadFile(dir + "/schema.sql")
	if err != nil {
		return nil, err
	}
	q.Schema = string(schema)

	// Load refresh tokens
	refreshTokens, err := fs.ReadFile(dir + "/refresh_tokens.sql")
	if err != nil {
		return nil, err
	}
	parsed := parseNamedQueries(string(refreshTokens))
	q.InsertRefreshToken = parsed["InsertRefreshToken"]
	q.SelectRefreshToken = parsed["SelectRefreshToken"]
	q.RevokeRefreshToken = parsed["RevokeRefreshToken"]
	q.RevokeTokenFamily = parsed["RevokeTokenFamily"]
	q.RevokeAllUserTokens = parsed["RevokeAllUserRefreshTokens"]
	q.DeleteExpiredTokens = parsed["DeleteExpiredRefreshTokens"]

	// Load blacklist
	blacklist, err := fs.ReadFile(dir + "/blacklist.sql")
	if err != nil {
		return nil, err
	}
	parsed = parseNamedQueries(string(blacklist))
	q.InsertBlacklist = parsed["InsertBlacklist"]
	q.SelectBlacklist = parsed["SelectBlacklist"]
	q.DeleteExpiredBlacklist = parsed["DeleteExpiredBlacklistEntries"]

	// Load permissions
	permissions, err := fs.ReadFile(dir + "/permissions.sql")
	if err != nil {
		return nil, err
	}
	parsed = parseNamedQueries(string(permissions))
	q.SelectUserPerms = parsed["SelectUserPermissions"]
	q.UpsertUserPerms = parsed["UpsertUserPermissions"]
	q.DeleteUserPerms = parsed["DeleteUserPermissions"]
	q.UpdateUsersWithRole = parsed["UpdateUsersWithRole"]

	// Load roles
	roles, err := fs.ReadFile(dir + "/roles.sql")
	if err != nil {
		return nil, err
	}
	parsed = parseNamedQueries(string(roles))
	q.SelectRoleTemplates = parsed["SelectRoleTemplates"]
	q.UpsertRoleTemplate = parsed["UpsertRoleTemplate"]

	// Load API keys
	apiKeys, err := fs.ReadFile(dir + "/api_keys.sql")
	if err != nil {
		return nil, err
	}
	parsed = parseNamedQueries(string(apiKeys))
	q.InsertAPIKey = parsed["InsertAPIKey"]
	q.SelectAPIKeyByHash = parsed["SelectAPIKeyByHash"]
	q.SelectAPIKeysByUser = parsed["SelectAPIKeysByUser"]
	q.RevokeAPIKey = parsed["RevokeAPIKey"]
	q.DeleteExpiredAPIKeys = parsed["DeleteExpiredAPIKeys"]

	return q, nil
}

// parseNamedQueries parses SQL content with -- name: comments.
func parseNamedQueries(content string) map[string]string {
	result := make(map[string]string)

	// Split by "-- name:" prefix
	parts := strings.Split(content, "-- name:")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// First line is the query name, rest is the SQL
		lines := strings.SplitN(part, "\n", 2)
		if len(lines) < 2 {
			continue
		}

		name := strings.TrimSpace(lines[0])
		query := strings.TrimSpace(lines[1])
		if name != "" && query != "" {
			result[name] = query
		}
	}

	return result
}
