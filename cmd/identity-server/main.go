// Command identity-server runs the OAuth 2.0 identity server.
//
// It can run on the net/http ServeMux, chi, gin, httprouter, gorilla/mux or echo, and store
// its data in memory, SQLite, PostgreSQL, MySQL or MongoDB. See -help for the options.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/mail"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/server"
	"github.com/deb-ict/go-identity/pkg/store"
	"github.com/deb-ict/go-identity/pkg/store/memory"
	chirouter "github.com/deb-ict/go-identity/router/chi"
	echorouter "github.com/deb-ict/go-identity/router/echo"
	ginrouter "github.com/deb-ict/go-identity/router/gin"
	muxrouter "github.com/deb-ict/go-identity/router/gorillamux"
	httprouteradapter "github.com/deb-ict/go-identity/router/httprouter"
	mongostore "github.com/deb-ict/go-identity/store/mongo"
	sqlstore "github.com/deb-ict/go-identity/store/sql"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/julienschmidt/httprouter"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func main() {
	cfg, err := ParseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func run(ctx context.Context, cfg *Config, logger *slog.Logger) error {
	s, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	var mailer mail.Sender = &mail.LogSender{Logger: logger}
	if cfg.SMTPHost != "" {
		mailer = mail.NewSMTPSender(mail.SMTPConfig{
			Host:        cfg.SMTPHost,
			Port:        cfg.SMTPPort,
			Username:    cfg.SMTPUsername,
			Password:    cfg.SMTPPassword,
			From:        cfg.SMTPFrom,
			ImplicitTLS: cfg.SMTPImplicitTLS,
		})
	}

	srv, err := server.New(server.Config{
		Store:             s,
		PublicURL:         cfg.PublicURL,
		BasePath:          cfg.BasePath,
		ApplicationName:   cfg.ApplicationName,
		SessionKey:        []byte(cfg.SessionKey),
		Mailer:            mailer,
		AllowRegistration: cfg.AllowRegistration,
		DisableActivation: cfg.DisableActivation,
		Logger:            logger,
	})
	if err != nil {
		return err
	}

	if cfg.AdminClientId != "" {
		_, err := srv.EnsureClient(ctx, &identity.Client{
			ClientId:          cfg.AdminClientId,
			Name:              "Identity administration",
			Type:              identity.ClientTypeConfidential,
			AllowedGrantTypes: []identity.GrantType{identity.GrantTypeClientCredentials},
			AllowedScopes:     []string{srv.Config().AdminScope},
			DefaultScopes:     []string{srv.Config().AdminScope},
			Enabled:           true,
		}, cfg.AdminClientSecret)
		if err != nil {
			return fmt.Errorf("failed to provision the admin client: %w", err)
		}
		logger.Info("admin client provisioned", "client_id", cfg.AdminClientId)
	}

	handler, err := newRouter(cfg.Router, srv)
	if err != nil {
		return err
	}

	go srv.RunCleanup(ctx, cfg.CleanupInterval)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errs := make(chan error, 1)
	go func() {
		logger.Info("identity server listening", "addr", cfg.Addr, "public_url", cfg.PublicURL, "router", cfg.Router, "database", cfg.DatabaseDriver)
		errs <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// newRouter mounts the identity server on the selected router.
func newRouter(name string, srv *server.Server) (http.Handler, error) {
	switch strings.ToLower(name) {
	case "std":
		mux := router.NewServeMux()
		srv.RegisterRoutes(mux)
		return mux, nil
	case "chi":
		r := chi.NewRouter()
		srv.RegisterRoutes(chirouter.New(r))
		return r, nil
	case "gin":
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(gin.Recovery())
		srv.RegisterRoutes(ginrouter.New(r))
		return r, nil
	case "httprouter":
		r := httprouter.New()
		srv.RegisterRoutes(httprouteradapter.New(r))
		return r, nil
	case "gorillamux":
		r := mux.NewRouter()
		srv.RegisterRoutes(muxrouter.New(r))
		return r, nil
	case "echo":
		e := echo.New()
		e.HideBanner = true
		e.HidePort = true
		srv.RegisterRoutes(echorouter.New(e))
		return e, nil
	}
	return nil, fmt.Errorf("unsupported router %q", name)
}

// openStore connects to the selected database and prepares the schema.
func openStore(ctx context.Context, cfg *Config) (store.Store, func(), error) {
	switch cfg.DatabaseDriver {
	case "memory":
		return memory.New(), func() {}, nil
	case "mongo":
		client, err := mongo.Connect(options.Client().ApplyURI(cfg.DatabaseDSN))
		if err != nil {
			return nil, nil, err
		}
		closeFn := func() { client.Disconnect(context.Background()) }
		s := mongostore.New(client.Database(cfg.DatabaseName), mongostore.Options{})
		if err := s.EnsureIndexes(ctx); err != nil {
			closeFn()
			return nil, nil, err
		}
		return s, closeFn, nil
	}

	driver, dialect := map[string]string{"sqlite": "sqlite", "postgres": "pgx", "mysql": "mysql"}[cfg.DatabaseDriver], sqlstore.Dialect(cfg.DatabaseDriver)
	db, err := sql.Open(driver, cfg.DatabaseDSN)
	if err != nil {
		return nil, nil, err
	}
	closeFn := func() { db.Close() }
	if dialect == sqlstore.DialectSQLite {
		// SQLite allows a single writer
		db.SetMaxOpenConns(1)
	}
	if err := db.PingContext(ctx); err != nil {
		closeFn()
		return nil, nil, err
	}
	s, err := sqlstore.New(db, sqlstore.Options{Dialect: dialect})
	if err == nil {
		err = s.Migrate(ctx)
	}
	if err != nil {
		closeFn()
		return nil, nil, err
	}
	return s, closeFn, nil
}
