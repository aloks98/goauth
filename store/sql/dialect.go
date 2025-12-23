// Package sql provides SQL database storage for goauth.
package sql

import (
	"strings"

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

// Default table prefix used in SQL files.
const defaultTablePrefix = "goauth_"

// getDialectQueries returns the queries for a specific dialect with the given table prefix.
func getDialectQueries(d Dialect, tablePrefix string) *dialectQueries {
	var dq *dialectQueries
	switch d {
	case MySQL:
		dq = getMySQLQueries()
	default:
		dq = getPostgreSQLQueries()
	}

	// Apply custom table prefix if different from default
	if tablePrefix != defaultTablePrefix {
		dq = applyTablePrefix(dq, tablePrefix)
	}

	return dq
}

// applyTablePrefix replaces the default table prefix with a custom one in all queries.
func applyTablePrefix(dq *dialectQueries, prefix string) *dialectQueries {
	replace := func(s string) string {
		return strings.ReplaceAll(s, defaultTablePrefix, prefix)
	}

	return &dialectQueries{
		placeholder: dq.placeholder,

		schema: replace(dq.schema),

		insertRefreshToken:         replace(dq.insertRefreshToken),
		selectRefreshToken:         replace(dq.selectRefreshToken),
		revokeRefreshToken:         replace(dq.revokeRefreshToken),
		revokeTokenFamily:          replace(dq.revokeTokenFamily),
		revokeAllUserRefreshTokens: replace(dq.revokeAllUserRefreshTokens),
		deleteExpiredRefreshTokens: replace(dq.deleteExpiredRefreshTokens),

		insertBlacklist:               replace(dq.insertBlacklist),
		selectBlacklist:               replace(dq.selectBlacklist),
		deleteExpiredBlacklistEntries: replace(dq.deleteExpiredBlacklistEntries),

		selectUserPermissions: replace(dq.selectUserPermissions),
		upsertUserPermissions: replace(dq.upsertUserPermissions),
		deleteUserPermissions: replace(dq.deleteUserPermissions),
		updateUsersWithRole:   replace(dq.updateUsersWithRole),

		selectRoleTemplates: replace(dq.selectRoleTemplates),
		upsertRoleTemplate:  replace(dq.upsertRoleTemplate),

		insertAPIKey:         replace(dq.insertAPIKey),
		selectAPIKeyByHash:   replace(dq.selectAPIKeyByHash),
		selectAPIKeysByUser:  replace(dq.selectAPIKeysByUser),
		revokeAPIKey:         replace(dq.revokeAPIKey),
		deleteExpiredAPIKeys: replace(dq.deleteExpiredAPIKeys),
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
