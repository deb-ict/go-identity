package sqlstore

import (
	"context"
	"fmt"
	"strings"
)

// Table names (without prefix)
const (
	tableClients            = "clients"
	tableUsers              = "users"
	tableAccessTokens       = "access_tokens"
	tableRefreshTokens      = "refresh_tokens"
	tableAuthorizationCodes = "authorization_codes"
	tableUserTokens         = "user_tokens"
)

// Portable column types
type columnType int

const (
	colKey     columnType = iota // short, indexable string: VARCHAR(255)
	colText                      // long string: TEXT
	colInt                       // BIGINT (unix nanoseconds, durations, counters)
	colNullInt                   // nullable BIGINT (optional times)
	colBool                      // BOOLEAN
)

type column struct {
	name string
	typ  columnType
}

type tableSpec struct {
	name    string
	columns []column
	// unique lists columns with a unique constraint, next to the "id" primary key.
	unique []string
	// indexes lists columns with a non-unique index.
	indexes []string
}

var schema = []tableSpec{
	{
		name: tableClients,
		columns: []column{
			{"id", colKey},
			{"client_id", colKey},
			{"name", colText},
			{"description", colText},
			{"client_type", colKey},
			{"secret_hash", colText},
			{"redirect_uris", colText},
			{"allowed_scopes", colText},
			{"default_scopes", colText},
			{"allowed_grant_types", colText},
			{"require_consent", colBool},
			{"require_pkce", colBool},
			{"enabled", colBool},
			{"access_token_lifetime", colInt},
			{"authorization_code_lifetime", colInt},
			{"refresh_token_usage", colKey},
			{"refresh_token_expiration", colKey},
			{"refresh_token_lifetime", colInt},
			{"created_at", colInt},
			{"updated_at", colInt},
		},
		unique:  []string{"client_id"},
		indexes: []string{"created_at"},
	},
	{
		name: tableUsers,
		columns: []column{
			{"id", colKey},
			{"username", colKey},
			{"normalized_username", colKey},
			{"email", colKey},
			{"normalized_email", colKey},
			{"password_hash", colText},
			{"email_verified", colBool},
			{"enabled", colBool},
			{"security_stamp", colText},
			{"failed_login_count", colInt},
			{"lockout_end", colNullInt},
			{"last_login_at", colNullInt},
			{"created_at", colInt},
			{"updated_at", colInt},
		},
		unique:  []string{"normalized_username", "normalized_email"},
		indexes: []string{"created_at"},
	},
	{
		name: tableAccessTokens,
		columns: []column{
			{"id", colKey},
			{"token_hash", colKey},
			{"client_id", colKey},
			{"user_id", colKey},
			{"scopes", colText},
			{"authorization_code_id", colKey},
			{"created_at", colInt},
			{"expires_at", colInt},
		},
		unique:  []string{"token_hash"},
		indexes: []string{"client_id", "user_id", "authorization_code_id", "expires_at", "created_at"},
	},
	{
		name: tableRefreshTokens,
		columns: []column{
			{"id", colKey},
			{"token_hash", colKey},
			{"client_id", colKey},
			{"user_id", colKey},
			{"access_token_id", colKey},
			{"authorization_code_id", colKey},
			{"scopes", colText},
			{"token_expiration", colKey},
			{"token_usage", colKey},
			{"lifetime", colInt},
			{"created_at", colInt},
			{"updated_at", colInt},
			{"expires_at", colInt},
		},
		unique:  []string{"token_hash"},
		indexes: []string{"client_id", "user_id", "authorization_code_id", "expires_at", "created_at"},
	},
	{
		name: tableAuthorizationCodes,
		columns: []column{
			{"id", colKey},
			{"code_hash", colKey},
			{"client_id", colKey},
			{"user_id", colKey},
			{"scopes", colText},
			{"redirect_uri", colText},
			{"code_challenge", colText},
			{"code_challenge_method", colKey},
			{"created_at", colInt},
			{"expires_at", colInt},
			{"consumed_at", colNullInt},
		},
		unique:  []string{"code_hash"},
		indexes: []string{"client_id", "user_id", "expires_at"},
	},
	{
		name: tableUserTokens,
		columns: []column{
			{"id", colKey},
			{"user_id", colKey},
			{"purpose", colKey},
			{"token_hash", colKey},
			{"created_at", colInt},
			{"expires_at", colInt},
		},
		unique:  []string{"token_hash"},
		indexes: []string{"user_id", "expires_at"},
	},
}

func (s *Store) columnDefinition(c column) string {
	switch c.typ {
	case colKey:
		if s.dialect == DialectPostgres {
			// Byte-wise comparison and ordering, like the other dialects
			return `VARCHAR(255) COLLATE "C" NOT NULL`
		}
		return "VARCHAR(255) NOT NULL"
	case colText:
		return "TEXT NOT NULL"
	case colInt:
		return "BIGINT NOT NULL"
	case colNullInt:
		return "BIGINT NULL"
	case colBool:
		return "BOOLEAN NOT NULL"
	}
	panic(fmt.Sprintf("sqlstore: unknown column type %d", c.typ))
}

// schemaStatements returns the DDL statements that create the schema.
func (s *Store) schemaStatements() []string {
	statements := []string{}
	for _, spec := range schema {
		table := s.table(spec.name)
		defs := []string{}
		for _, c := range spec.columns {
			defs = append(defs, c.name+" "+s.columnDefinition(c))
		}
		defs = append(defs, "PRIMARY KEY (id)")
		for _, col := range spec.unique {
			defs = append(defs, "CONSTRAINT "+table+"_"+col+"_key UNIQUE ("+col+")")
		}
		if s.dialect == DialectMySQL {
			// MySQL doesn't support CREATE INDEX IF NOT EXISTS
			for _, col := range spec.indexes {
				defs = append(defs, "INDEX "+table+"_"+col+"_idx ("+col+")")
			}
		}
		ddl := "CREATE TABLE IF NOT EXISTS " + table + " (\n\t" + strings.Join(defs, ",\n\t") + "\n)"
		if s.dialect == DialectMySQL {
			ddl += " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"
		}
		statements = append(statements, ddl)
		if s.dialect != DialectMySQL {
			for _, col := range spec.indexes {
				statements = append(statements, "CREATE INDEX IF NOT EXISTS "+table+"_"+col+"_idx ON "+table+" ("+col+")")
			}
		}
	}
	return statements
}

// Migrate creates the tables and indexes when they don't exist. It is safe to call it multiple times.
func (s *Store) Migrate(ctx context.Context) error {
	for _, statement := range s.schemaStatements() {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}
	return nil
}

// columnList returns the comma separated column names of a table.
func columnList(name string) string {
	for _, spec := range schema {
		if spec.name == name {
			names := make([]string, len(spec.columns))
			for i, c := range spec.columns {
				names[i] = c.name
			}
			return strings.Join(names, ", ")
		}
	}
	panic("sqlstore: unknown table " + name)
}
