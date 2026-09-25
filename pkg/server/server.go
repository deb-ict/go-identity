// Package server assembles the identity server: the OAuth 2.0 authorization server, the
// login/registration/activation/password reset UI and the management API.
//
//	srv, err := server.New(server.Config{
//		Store:      memory.New(),
//		PublicURL:  "https://id.example.com",
//		SessionKey: key,
//	})
//	mux := router.NewServeMux()          // or chirouter.New(chi.NewRouter()), ginrouter.New(gin.New()), ...
//	srv.RegisterRoutes(mux)
//	http.ListenAndServe(":8080", mux)
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deb-ict/go-identity/pkg/account"
	"github.com/deb-ict/go-identity/pkg/api"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/mail"
	"github.com/deb-ict/go-identity/pkg/oauth"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/session"
	"github.com/deb-ict/go-identity/pkg/store"
	"github.com/deb-ict/go-identity/pkg/ui"
)

// DefaultAdminScope is the scope required by the management API.
const DefaultAdminScope = "identity.admin"

// Config configures the identity server.
type Config struct {
	// Store persists clients, users and tokens.
	Store store.Store
	// PublicURL is the external URL of the server, including the path it's mounted on,
	// e.g. "https://example.com/identity". It is the OAuth issuer and is used in emails.
	PublicURL string
	// BasePath is the path prefix of all routes. It defaults to the path of the PublicURL.
	// Set it explicitly when a reverse proxy rewrites the path.
	BasePath string
	// ApplicationName is shown in the UI and the emails.
	ApplicationName string
	// SessionKey signs the session and CSRF cookies. It must have at least 32 bytes and must be
	// the same on all instances. When empty, a random key is generated (sessions don't survive a restart).
	SessionKey      []byte
	SessionLifetime time.Duration
	// InsecureCookies allows the session cookie over plain HTTP. By default cookies are only marked
	// Secure when the PublicURL uses https.
	InsecureCookies bool
	// Mailer sends the activation and password reset emails. Defaults to logging the emails.
	Mailer mail.Sender
	// PasswordHasher hashes user passwords and client secrets. Defaults to bcrypt.
	PasswordHasher security.PasswordHasher
	// AllowRegistration enables self registration in the UI.
	AllowRegistration bool
	// DisableActivation lets users sign in without confirming their email address.
	DisableActivation bool
	MinPasswordLength int
	// MaxFailedAttempts locks an account after consecutive failed logins. Defaults to 5; negative disables lockout.
	MaxFailedAttempts int
	LockoutDuration   time.Duration
	// AdminScope is required on access tokens used for the management API.
	AdminScope string
	// DisableAPI doesn't register the management API.
	DisableAPI bool
	// Templates overrides the UI templates, see package ui.
	Templates fs.FS
	// TokenGenerator generates access tokens. Defaults to opaque random tokens.
	TokenGenerator oauth.TokenGenerator
	// ScopesSupported is published in the metadata document.
	ScopesSupported []string
	Logger          *slog.Logger
	Now             func() time.Time
}

// Server is the assembled identity server.
type Server struct {
	cfg      Config
	Accounts *account.Service
	Sessions *session.Manager
	OAuth    *oauth.Server
	UI       *ui.UI
	API      *api.API
}

type links struct {
	publicURL string
}

func (l links) ActivationURL(token string) string {
	return l.publicURL + ui.PathActivate + "?" + url.Values{"token": {token}}.Encode()
}

func (l links) PasswordResetURL(token string) string {
	return l.publicURL + ui.PathPasswordReset + "?" + url.Values{"token": {token}}.Encode()
}

// New creates the identity server.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("server: a store is required")
	}
	publicURL, err := url.Parse(cfg.PublicURL)
	if err != nil || publicURL.Scheme == "" || publicURL.Host == "" {
		return nil, fmt.Errorf("server: the public url %q must be an absolute URL", cfg.PublicURL)
	}
	cfg.PublicURL = strings.TrimSuffix(cfg.PublicURL, "/")
	if cfg.BasePath == "" {
		cfg.BasePath = publicURL.Path
	}
	cfg.BasePath = strings.TrimSuffix(cfg.BasePath, "/")
	if cfg.BasePath != "" && !strings.HasPrefix(cfg.BasePath, "/") {
		return nil, errors.New("server: the base path must start with '/'")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ApplicationName == "" {
		cfg.ApplicationName = "Identity"
	}
	if cfg.AdminScope == "" {
		cfg.AdminScope = DefaultAdminScope
	}
	if cfg.PasswordHasher == nil {
		cfg.PasswordHasher = security.NewBcryptHasher(0)
	}
	if cfg.Mailer == nil {
		cfg.Mailer = &mail.LogSender{Logger: cfg.Logger}
	}
	if cfg.MaxFailedAttempts == 0 {
		cfg.MaxFailedAttempts = 5
	} else if cfg.MaxFailedAttempts < 0 {
		cfg.MaxFailedAttempts = 0
	}
	if len(cfg.SessionKey) == 0 {
		cfg.Logger.Warn("no session key configured, using a random key: sessions won't survive a restart")
		cfg.SessionKey = security.RandomBytes(32)
	}

	s := &Server{cfg: cfg}
	s.Accounts = account.New(account.Options{
		Store:             cfg.Store,
		Hasher:            cfg.PasswordHasher,
		Mailer:            cfg.Mailer,
		Links:             links{publicURL: cfg.PublicURL},
		ApplicationName:   cfg.ApplicationName,
		RequireActivation: !cfg.DisableActivation,
		MinPasswordLength: cfg.MinPasswordLength,
		MaxFailedAttempts: cfg.MaxFailedAttempts,
		LockoutDuration:   cfg.LockoutDuration,
		Now:               cfg.Now,
		Logger:            cfg.Logger,
	})

	cookiePath := cfg.BasePath
	if cookiePath == "" {
		cookiePath = "/"
	}
	s.Sessions, err = session.NewManager(session.Options{
		Key:      cfg.SessionKey,
		Path:     cookiePath,
		Secure:   publicURL.Scheme == "https" && !cfg.InsecureCookies,
		Lifetime: cfg.SessionLifetime,
		Now:      cfg.Now,
	})
	if err != nil {
		return nil, err
	}

	s.UI, err = ui.New(ui.Options{
		Accounts:          s.Accounts,
		Sessions:          s.Sessions,
		BasePath:          cfg.BasePath,
		ApplicationName:   cfg.ApplicationName,
		AllowRegistration: cfg.AllowRegistration,
		Templates:         cfg.Templates,
		Logger:            cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	s.OAuth, err = oauth.New(oauth.Options{
		Store:           cfg.Store,
		Accounts:        s.Accounts,
		Hasher:          cfg.PasswordHasher,
		Interaction:     s.UI,
		Issuer:          cfg.PublicURL,
		BasePath:        cfg.BasePath,
		TokenGenerator:  cfg.TokenGenerator,
		ScopesSupported: cfg.ScopesSupported,
		Now:             cfg.Now,
		Logger:          cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	if !cfg.DisableAPI {
		s.API, err = api.New(api.Options{
			Store:      cfg.Store,
			Accounts:   s.Accounts,
			Hasher:     cfg.PasswordHasher,
			Middleware: []router.Middleware{s.OAuth.RequireBearer(cfg.AdminScope)},
			Now:        cfg.Now,
			Logger:     cfg.Logger,
		})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Config returns the effective configuration.
func (s *Server) Config() Config {
	return s.cfg
}

// RegisterRoutes registers all routes below the base path.
func (s *Server) RegisterRoutes(r router.Router) {
	r = router.WithPrefix(r, s.cfg.BasePath)
	s.OAuth.RegisterRoutes(r)
	s.UI.RegisterRoutes(r)
	if s.API != nil {
		s.API.RegisterRoutes(r)
	}
}

// Handler returns an http.Handler serving all routes, using the net/http ServeMux.
func (s *Server) Handler() http.Handler {
	mux := router.NewServeMux()
	s.RegisterRoutes(mux)
	return mux
}

// Cleanup deletes the expired tokens, authorization codes and user tokens.
func (s *Server) Cleanup(ctx context.Context) error {
	return store.DeleteExpired(ctx, s.cfg.Store, s.cfg.Now().UTC())
}

// RunCleanup calls Cleanup at every interval, until the context is done.
func (s *Server) RunCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Cleanup(ctx); err != nil && ctx.Err() == nil {
				s.cfg.Logger.ErrorContext(ctx, "failed to delete expired tokens", "error", err)
			}
		}
	}
}

// EnsureClient creates the client, or updates the existing client with the same client_id.
// When a secret is given, it becomes the client secret. Use it to provision clients at startup.
func (s *Server) EnsureClient(ctx context.Context, client *identity.Client, secret string) (*identity.Client, error) {
	now := s.cfg.Now().UTC().Truncate(time.Millisecond)
	existing, err := s.cfg.Store.GetClientByClientId(ctx, client.ClientId)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	c := *client
	c.EnsureDefaults()
	if secret != "" {
		if c.SecretHash, err = s.cfg.PasswordHasher.Hash(secret); err != nil {
			return nil, err
		}
	} else if existing != nil {
		c.SecretHash = existing.SecretHash
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.UpdatedAt = now
	if existing != nil {
		c.Id = existing.Id
		c.CreatedAt = existing.CreatedAt
		return &c, s.cfg.Store.UpdateClient(ctx, &c)
	}
	if c.Id == "" {
		c.Id = security.NewId()
	}
	c.CreatedAt = now
	return &c, s.cfg.Store.CreateClient(ctx, &c)
}
