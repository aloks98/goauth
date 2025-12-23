// Package sql provides SQL database storage for goauth.
package sql

import (
	"github.com/aloks98/goauth/store/sql/queries"
)

// Dialect represents a SQL database dialect.
type Dialect string

const (
	// PostgreSQL dialect.
	PostgreSQL Dialect = "postgres"
	// MySQL dialect.
	MySQL Dialect = "mysql"
)

// dialectQueries contains SQL queries for each dialect.
type dialectQueries struct {
	// Schema creation (combined into single string for migration)
	schema string

	// Refresh tokens
	insertRefreshToken         string
	selectRefreshToken         string
	revokeRefreshToken         string
	revokeTokenFamily          string
	revokeAllUserRefreshTokens string
	deleteExpiredRefreshTokens string

	// Blacklist
	insertBlacklist               string
	selectBlacklist               string
	deleteExpiredBlacklistEntries string

	// User permissions
	selectUserPermissions string
	upsertUserPermissions string
	deleteUserPermissions string
	updateUsersWithRole   string

	// Role templates
	selectRoleTemplates string
	upsertRoleTemplate  string

	// API keys
	insertAPIKey         string
	selectAPIKeyByHash   string
	selectAPIKeysByUser  string
	revokeAPIKey         string
	deleteExpiredAPIKeys string

	// Placeholders
	placeholder func(int) string
}

// getDialectQueries returns the queries for a specific dialect.
func getDialectQueries(d Dialect) *dialectQueries {
	switch d {
	case MySQL:
		return getMySQLQueries()
	default:
		return getPostgreSQLQueries()
	}
}

func getPostgreSQLQueries() *dialectQueries {
	q, err := queries.LoadPostgres()
	if err != nil {
		panic("failed to load postgres queries: " + err.Error())
	}

	return &dialectQueries{
		placeholder: postgresPlaceholder,

		schema: q.Schema,

		insertRefreshToken:         q.InsertRefreshToken,
		selectRefreshToken:         q.SelectRefreshToken,
		revokeRefreshToken:         q.RevokeRefreshToken,
		revokeTokenFamily:          q.RevokeTokenFamily,
		revokeAllUserRefreshTokens: q.RevokeAllUserTokens,
		deleteExpiredRefreshTokens: q.DeleteExpiredTokens,

		insertBlacklist:               q.InsertBlacklist,
		selectBlacklist:               q.SelectBlacklist,
		deleteExpiredBlacklistEntries: q.DeleteExpiredBlacklist,

		selectUserPermissions: q.SelectUserPerms,
		upsertUserPermissions: q.UpsertUserPerms,
		deleteUserPermissions: q.DeleteUserPerms,
		updateUsersWithRole:   q.UpdateUsersWithRole,

		selectRoleTemplates: q.SelectRoleTemplates,
		upsertRoleTemplate:  q.UpsertRoleTemplate,

		insertAPIKey:         q.InsertAPIKey,
		selectAPIKeyByHash:   q.SelectAPIKeyByHash,
		selectAPIKeysByUser:  q.SelectAPIKeysByUser,
		revokeAPIKey:         q.RevokeAPIKey,
		deleteExpiredAPIKeys: q.DeleteExpiredAPIKeys,
	}
}

func getMySQLQueries() *dialectQueries {
	q, err := queries.LoadMySQL()
	if err != nil {
		panic("failed to load mysql queries: " + err.Error())
	}

	return &dialectQueries{
		placeholder: mysqlPlaceholder,

		schema: q.Schema,

		insertRefreshToken:         q.InsertRefreshToken,
		selectRefreshToken:         q.SelectRefreshToken,
		revokeRefreshToken:         q.RevokeRefreshToken,
		revokeTokenFamily:          q.RevokeTokenFamily,
		revokeAllUserRefreshTokens: q.RevokeAllUserTokens,
		deleteExpiredRefreshTokens: q.DeleteExpiredTokens,

		insertBlacklist:               q.InsertBlacklist,
		selectBlacklist:               q.SelectBlacklist,
		deleteExpiredBlacklistEntries: q.DeleteExpiredBlacklist,

		selectUserPermissions: q.SelectUserPerms,
		upsertUserPermissions: q.UpsertUserPerms,
		deleteUserPermissions: q.DeleteUserPerms,
		updateUsersWithRole:   q.UpdateUsersWithRole,

		selectRoleTemplates: q.SelectRoleTemplates,
		upsertRoleTemplate:  q.UpsertRoleTemplate,

		insertAPIKey:         q.InsertAPIKey,
		selectAPIKeyByHash:   q.SelectAPIKeyByHash,
		selectAPIKeysByUser:  q.SelectAPIKeysByUser,
		revokeAPIKey:         q.RevokeAPIKey,
		deleteExpiredAPIKeys: q.DeleteExpiredAPIKeys,
	}
}

// placeholder functions for different dialects
func postgresPlaceholder(n int) string {
	return "$" + itoa(n)
}

func mysqlPlaceholder(_ int) string {
	return "?"
}

// itoa converts int to string without importing strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
