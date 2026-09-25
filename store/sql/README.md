# sqlstore

`github.com/deb-ict/go-identity/store/sql` implements `store.Store` on top of `database/sql`
for PostgreSQL, MySQL (5.7+ / MariaDB 10.2+, InnoDB) and SQLite.

The package doesn't import a driver: open the `*sql.DB` with the driver you prefer.

```sh
go get github.com/deb-ict/go-identity/store/sql
```

## PostgreSQL

```go
import (
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
	sqlstore "github.com/deb-ict/go-identity/store/sql"
)

db, err := sql.Open("pgx", "postgres://user:pass@localhost:5432/identity?sslmode=disable")
if err != nil {
	return err
}
s, err := sqlstore.New(db, sqlstore.Options{Dialect: sqlstore.DialectPostgres})
if err != nil {
	return err
}
if err := s.Migrate(ctx); err != nil {
	return err
}
```

## MySQL

```go
import _ "github.com/go-sql-driver/mysql"

db, err := sql.Open("mysql", "user:pass@tcp(localhost:3306)/identity")
s, err := sqlstore.New(db, sqlstore.Options{Dialect: sqlstore.DialectMySQL})
err = s.Migrate(ctx)
```

Tables are created with `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`, so
identifiers and hashes compare case sensitively.

## SQLite

```go
import _ "modernc.org/sqlite" // pure Go, or github.com/mattn/go-sqlite3 (driver name "sqlite3")

db, err := sql.Open("sqlite", "file:identity.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
s, err := sqlstore.New(db, sqlstore.Options{Dialect: sqlstore.DialectSQLite})
err = s.Migrate(ctx)
```

## Options

| Option        | Description                                                              |
|---------------|--------------------------------------------------------------------------|
| `Dialect`     | `DialectPostgres`, `DialectMySQL` or `DialectSQLite` (required).         |
| `TablePrefix` | Prefix of table and index names, default `identity_`. Letters, digits and `_` only. |

`Migrate` runs `CREATE TABLE IF NOT EXISTS` (and `CREATE INDEX IF NOT EXISTS` on PostgreSQL and
SQLite; MySQL indexes are declared in the table definition) and can be called at every start.

## Schema notes

- Identifiers and indexed strings are `VARCHAR(255)`, long values `TEXT`.
- Lists (redirect URIs, scopes, grant types) are stored as JSON arrays in `TEXT` columns.
- Times are stored as `BIGINT` unix nanoseconds (UTC), optional times as nullable `BIGINT`,
  durations as `BIGINT` nanoseconds. A zero `time.Time` is stored as `0`.

## Tests

The SQLite tests always run. The PostgreSQL and MySQL tests run when a DSN is set:

```sh
IDENTITY_TEST_POSTGRES_DSN="postgres://user:pass@localhost:5432/identity_test?sslmode=disable" \
IDENTITY_TEST_MYSQL_DSN="user:pass@tcp(localhost:3306)/identity_test" \
go test ./...
```

Every test store uses its own table prefix; the tables are dropped afterwards.
