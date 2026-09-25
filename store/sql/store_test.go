package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/store"
	"github.com/deb-ict/go-identity/pkg/store/storetest"
)

func newStore(t *testing.T, db *sql.DB, dialect Dialect, prefix string) *Store {
	t.Helper()
	s, err := New(db, Options{Dialect: dialect, TablePrefix: prefix})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ctx := context.Background()
	// Migrate twice to prove it is idempotent
	for i := 0; i < 2; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate (%d): %v", i+1, err)
		}
	}
	return s
}

func TestSQLite(t *testing.T) {
	runSuite(t, func(t *testing.T) store.Store {
		path := filepath.Join(t.TempDir(), "identity.db")
		db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		return newStore(t, db, DialectSQLite, "")
	})
}

// runSuite runs the conformance suite and the SQL specific tests.
func runSuite(t *testing.T, factory storetest.Factory) {
	storetest.Run(t, factory)
	t.Run("UpdateUnchanged", func(t *testing.T) { testUpdateUnchanged(t, factory(t)) })
}

// testUpdateUnchanged checks that an update that doesn't change any value succeeds
// (MySQL reports 0 affected rows in that case).
func testUpdateUnchanged(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	client := &identity.Client{Id: "c1", ClientId: "client", CreatedAt: now, UpdatedAt: now}
	client.EnsureDefaults()
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := s.UpdateClient(ctx, client); err != nil {
		t.Fatalf("unchanged client update: %v", err)
	}
	user := &identity.User{Id: "u1", Username: "alice", Email: "alice@example.com", CreatedAt: now, UpdatedAt: now}
	user.Normalize()
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := s.UpdateUser(ctx, user); err != nil {
		t.Fatalf("unchanged user update: %v", err)
	}
	token := &identity.RefreshToken{Id: "r1", TokenHash: "h", ClientId: "client", CreatedAt: now, UpdatedAt: now, ExpiresAt: now}
	if err := s.CreateRefreshToken(ctx, token); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if err := s.UpdateRefreshToken(ctx, token); err != nil {
		t.Fatalf("unchanged refresh token update: %v", err)
	}
	if err := s.UpdateUser(ctx, &identity.User{Id: "missing"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing user: expected not found, got %v", err)
	}
}

var prefixCounter atomic.Int64

// runServerTests runs the conformance suite against a database server. Every store uses its own
// table prefix, the tables are dropped afterwards.
func runServerTests(t *testing.T, driver string, envName string, dialect Dialect) {
	dsn := os.Getenv(envName)
	if dsn == "" {
		t.Skipf("%s not set", envName)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatalf("open %s: %v", driver, err)
	}
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping %s: %v", driver, err)
	}
	run := fmt.Sprintf("t%d_%d_", time.Now().UnixNano()%1_000_000, os.Getpid()%1000)

	runSuite(t, func(t *testing.T) store.Store {
		prefix := fmt.Sprintf("%s%d_", run, prefixCounter.Add(1))
		s := newStore(t, db, dialect, prefix)
		t.Cleanup(func() {
			for _, spec := range schema {
				if _, err := db.Exec("DROP TABLE IF EXISTS " + s.table(spec.name)); err != nil {
					t.Errorf("drop table: %v", err)
				}
			}
		})
		return s
	})
}

func TestPostgres(t *testing.T) {
	runServerTests(t, "pgx", "IDENTITY_TEST_POSTGRES_DSN", DialectPostgres)
}

func TestMySQL(t *testing.T) {
	runServerTests(t, "mysql", "IDENTITY_TEST_MYSQL_DSN", DialectMySQL)
}

func TestNew(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "new.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := New(nil, Options{Dialect: DialectSQLite}); err == nil {
		t.Error("expected error for nil db")
	}
	if _, err := New(db, Options{}); err == nil {
		t.Error("expected error for missing dialect")
	}
	if _, err := New(db, Options{Dialect: "oracle"}); err == nil {
		t.Error("expected error for unknown dialect")
	}
	if _, err := New(db, Options{Dialect: DialectSQLite, TablePrefix: "x; DROP TABLE y; --"}); err == nil {
		t.Error("expected error for invalid prefix")
	}
	s, err := New(db, Options{Dialect: DialectSQLite})
	if err != nil {
		t.Fatal(err)
	}
	if s.table(tableUsers) != "identity_users" {
		t.Errorf("unexpected default table name %q", s.table(tableUsers))
	}
}

func TestRebind(t *testing.T) {
	query := "SELECT a FROM t WHERE b = ? AND c LIKE '?%' AND d IN (?, ?)"
	if got := rebind(DialectPostgres, query); got != "SELECT a FROM t WHERE b = $1 AND c LIKE '?%' AND d IN ($2, $3)" {
		t.Errorf("postgres: %s", got)
	}
	for _, d := range []Dialect{DialectMySQL, DialectSQLite} {
		if got := rebind(d, query); got != query {
			t.Errorf("%s: %s", d, got)
		}
	}
}

func TestEscapeLike(t *testing.T) {
	if got := escapeLike("a%b_c!d"); got != "a!%b!_c!!d" {
		t.Errorf("unexpected escape: %s", got)
	}
}

func TestIsUniqueViolation(t *testing.T) {
	for _, msg := range []string{
		"constraint failed: UNIQUE constraint failed: identity_users.normalized_email (2067)",
		`ERROR: duplicate key value violates unique constraint "identity_users_pkey" (SQLSTATE 23505)`,
		"Error 1062 (23000): Duplicate entry 'x' for key 'identity_users.PRIMARY'",
	} {
		if !isUniqueViolation(errors.New(msg)) {
			t.Errorf("not recognized: %s", msg)
		}
		if !errors.Is(mapError(errors.New(msg)), store.ErrDuplicate) {
			t.Errorf("not mapped: %s", msg)
		}
	}
	if isUniqueViolation(errors.New("connection refused")) {
		t.Error("false positive")
	}
}

func TestTimeEncoding(t *testing.T) {
	if encTime(time.Time{}) != 0 || !decTime(0).IsZero() {
		t.Error("zero time must round trip")
	}
	loc := time.FixedZone("x", 3600)
	now := time.Date(2025, 5, 6, 7, 8, 9, 123456789, loc)
	got := decTime(encTime(now))
	if !got.Equal(now) || got.Location() != time.UTC {
		t.Errorf("unexpected time %v", got)
	}
}
