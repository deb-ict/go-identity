// Package sqlstore provides a store.Store backed by a SQL database.
//
// PostgreSQL, MySQL (5.7+/MariaDB 10.2+ with InnoDB) and SQLite are supported.
// The package only depends on database/sql: the caller opens the *sql.DB with
// the driver of choice, for example github.com/jackc/pgx/v5/stdlib,
// github.com/go-sql-driver/mysql or modernc.org/sqlite.
//
//	db, err := sql.Open("pgx", dsn)
//	s, err := sqlstore.New(db, sqlstore.Options{Dialect: sqlstore.DialectPostgres})
//	err = s.Migrate(ctx)
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deb-ict/go-identity/pkg/store"
)

// Dialect identifies the SQL dialect of the database.
type Dialect string

const (
	DialectPostgres Dialect = "postgres"
	DialectMySQL    Dialect = "mysql"
	DialectSQLite   Dialect = "sqlite"
)

// DefaultTablePrefix is used when Options.TablePrefix is empty.
const DefaultTablePrefix = "identity_"

// Options configures the SQL store.
type Options struct {
	// Dialect of the database (required).
	Dialect Dialect
	// TablePrefix is prepended to all table and index names. Defaults to "identity_".
	// It may only contain ASCII letters, digits and underscores.
	TablePrefix string
}

// Store implements store.Store on top of database/sql.
type Store struct {
	db      *sql.DB
	dialect Dialect
	prefix  string
}

var _ store.Store = (*Store)(nil)

// New creates a SQL store. It doesn't touch the database; call Migrate to create the schema.
func New(db *sql.DB, opts Options) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlstore: db is nil")
	}
	switch opts.Dialect {
	case DialectPostgres, DialectMySQL, DialectSQLite:
	default:
		return nil, fmt.Errorf("sqlstore: unsupported dialect %q", opts.Dialect)
	}
	prefix := opts.TablePrefix
	if prefix == "" {
		prefix = DefaultTablePrefix
	}
	if !isIdentifier(prefix) {
		return nil, fmt.Errorf("sqlstore: invalid table prefix %q", prefix)
	}
	return &Store{db: db, dialect: opts.Dialect, prefix: prefix}, nil
}

func isIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return s != ""
}

// table returns the prefixed table name.
func (s *Store) table(name string) string {
	return s.prefix + name
}

// rebind converts '?' placeholders to the placeholder syntax of the dialect.
// Question marks inside quoted strings are left alone.
func rebind(dialect Dialect, query string) string {
	if dialect != DialectPostgres || !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 16)
	n := 0
	var quote byte
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '?':
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, rebind(s.dialect, query), args...)
}

func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, rebind(s.dialect, query), args...)
}

func (s *Store) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, rebind(s.dialect, query), args...)
}

// execChanged runs an update or delete of a single row by id. When no row was affected
// it checks whether the row exists, because MySQL reports 0 affected rows for an update
// that doesn't change any value.
func (s *Store) execChanged(ctx context.Context, table string, id string, query string, args ...any) error {
	res, err := s.exec(ctx, query, args...)
	if err != nil {
		return mapError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	exists, err := s.exists(ctx, table, id)
	if err != nil {
		return err
	}
	if !exists {
		return store.ErrNotFound
	}
	return nil
}

// execDelete deletes a single row and returns ErrNotFound when nothing was deleted.
func (s *Store) execDelete(ctx context.Context, table string, id string) error {
	res, err := s.exec(ctx, "DELETE FROM "+table+" WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// execCount runs a statement and returns the number of affected rows.
func (s *Store) execCount(ctx context.Context, query string, args ...any) (int, error) {
	res, err := s.exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func (s *Store) exists(ctx context.Context, table string, id string) (bool, error) {
	var one int
	err := s.queryRow(ctx, "SELECT 1 FROM "+table+" WHERE id = ?", id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) count(ctx context.Context, table string, where string, args ...any) (int, error) {
	var total int
	if err := s.queryRow(ctx, "SELECT COUNT(*) FROM "+table+where, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// list runs a paged query ordered by creation time and id, and returns the items and the total count.
func list[T any](ctx context.Context, s *Store, table string, columns string, where string, args []any, opts store.ListOptions, scan func(scanner) (T, error)) ([]T, int, error) {
	opts = opts.Normalize()
	total, err := s.count(ctx, table, where, args...)
	if err != nil {
		return nil, 0, err
	}
	if total == 0 || opts.Offset >= total {
		return []T{}, total, nil
	}
	query := "SELECT " + columns + " FROM " + table + where + " ORDER BY created_at, id LIMIT ? OFFSET ?"
	pageArgs := append(append([]any{}, args...), opts.Limit, opts.Offset)
	rows, err := s.query(ctx, query, pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []T{}
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// getOne runs a query that returns at most one row.
func getOne[T any](row *sql.Row, scan func(scanner) (T, error)) (T, error) {
	item, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		var zero T
		return zero, store.ErrNotFound
	}
	return item, err
}

type scanner interface {
	Scan(dest ...any) error
}

// mapError converts unique constraint violations into store.ErrDuplicate.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: %v", store.ErrDuplicate, err)
	}
	return err
}

// isUniqueViolation recognizes unique constraint errors of the common drivers without importing them:
// SQLite "UNIQUE constraint failed", PostgreSQL "duplicate key value violates unique constraint" (SQLSTATE 23505)
// and MySQL "Error 1062: Duplicate entry".
func isUniqueViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate") || strings.Contains(msg, "23505")
}

// Value encoding

// encTime stores times as unix nanoseconds. The zero time is stored as 0.
func encTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func decTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

func encTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return encTime(*t)
}

func decTimePtr(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := decTime(n.Int64)
	return &t
}

func encList[T any](v []T) string {
	if v == nil {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		// Slices of strings can always be marshaled
		panic(err)
	}
	return string(b)
}

func decList[T any](s string) ([]T, error) {
	if s == "" {
		return nil, nil
	}
	var v []T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("sqlstore: invalid list value: %w", err)
	}
	return v, nil
}

// escapeLike escapes the LIKE wildcards with likeEscape.
func escapeLike(s string) string {
	r := strings.NewReplacer(likeEscape, likeEscape+likeEscape, "%", likeEscape+"%", "_", likeEscape+"_")
	return r.Replace(s)
}

// likeEscape is the escape character of LIKE patterns. A backslash is avoided because
// MySQL treats it as an escape character in string literals.
const likeEscape = "!"
