package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from command line flags, with environment variables as defaults.
type Config struct {
	Addr              string
	PublicURL         string
	BasePath          string
	ApplicationName   string
	SessionKey        string
	Router            string
	DatabaseDriver    string
	DatabaseDSN       string
	DatabaseName      string
	AllowRegistration bool
	DisableActivation bool
	AdminClientId     string
	AdminClientSecret string
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	SMTPImplicitTLS   bool
	CleanupInterval   time.Duration
	LogLevel          string
}

func env(name string, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	if v, ok := os.LookupEnv(name); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return fallback
}

func envInt(name string, fallback int) int {
	if v, ok := os.LookupEnv(name); ok {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(name); ok {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return fallback
}

// ParseConfig parses the flags and environment variables.
func ParseConfig(args []string) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("identity-server", flag.ContinueOnError)
	fs.StringVar(&c.Addr, "addr", env("IDENTITY_ADDR", ":8080"), "listen address [IDENTITY_ADDR]")
	fs.StringVar(&c.PublicURL, "public-url", env("IDENTITY_PUBLIC_URL", "http://localhost:8080"), "external URL including the base path, used as issuer [IDENTITY_PUBLIC_URL]")
	fs.StringVar(&c.BasePath, "base-path", env("IDENTITY_BASE_PATH", ""), "path prefix of the routes, defaults to the path of the public URL [IDENTITY_BASE_PATH]")
	fs.StringVar(&c.ApplicationName, "app-name", env("IDENTITY_APP_NAME", "Identity"), "name shown in the UI and emails [IDENTITY_APP_NAME]")
	fs.StringVar(&c.SessionKey, "session-key", env("IDENTITY_SESSION_KEY", ""), "secret of at least 32 characters to sign cookies [IDENTITY_SESSION_KEY]")
	fs.StringVar(&c.Router, "router", env("IDENTITY_ROUTER", "std"), "http router: std, chi, gin, httprouter, gorillamux or echo [IDENTITY_ROUTER]")
	fs.StringVar(&c.DatabaseDriver, "db-driver", env("IDENTITY_DB_DRIVER", "memory"), "database: memory, sqlite, postgres, mysql or mongo [IDENTITY_DB_DRIVER]")
	fs.StringVar(&c.DatabaseDSN, "db-dsn", env("IDENTITY_DB_DSN", ""), "database connection string [IDENTITY_DB_DSN]")
	fs.StringVar(&c.DatabaseName, "db-name", env("IDENTITY_DB_NAME", "identity"), "mongo database name [IDENTITY_DB_NAME]")
	fs.BoolVar(&c.AllowRegistration, "allow-registration", envBool("IDENTITY_ALLOW_REGISTRATION", false), "enable self registration [IDENTITY_ALLOW_REGISTRATION]")
	fs.BoolVar(&c.DisableActivation, "disable-activation", envBool("IDENTITY_DISABLE_ACTIVATION", false), "don't require email activation [IDENTITY_DISABLE_ACTIVATION]")
	fs.StringVar(&c.AdminClientId, "admin-client-id", env("IDENTITY_ADMIN_CLIENT_ID", ""), "client provisioned at startup for the management API [IDENTITY_ADMIN_CLIENT_ID]")
	fs.StringVar(&c.AdminClientSecret, "admin-client-secret", env("IDENTITY_ADMIN_CLIENT_SECRET", ""), "secret of the admin client [IDENTITY_ADMIN_CLIENT_SECRET]")
	fs.StringVar(&c.SMTPHost, "smtp-host", env("IDENTITY_SMTP_HOST", ""), "SMTP host, emails are logged when empty [IDENTITY_SMTP_HOST]")
	fs.IntVar(&c.SMTPPort, "smtp-port", envInt("IDENTITY_SMTP_PORT", 587), "SMTP port [IDENTITY_SMTP_PORT]")
	fs.StringVar(&c.SMTPUsername, "smtp-username", env("IDENTITY_SMTP_USERNAME", ""), "SMTP username [IDENTITY_SMTP_USERNAME]")
	fs.StringVar(&c.SMTPPassword, "smtp-password", env("IDENTITY_SMTP_PASSWORD", ""), "SMTP password [IDENTITY_SMTP_PASSWORD]")
	fs.StringVar(&c.SMTPFrom, "smtp-from", env("IDENTITY_SMTP_FROM", ""), "sender address [IDENTITY_SMTP_FROM]")
	fs.BoolVar(&c.SMTPImplicitTLS, "smtp-implicit-tls", envBool("IDENTITY_SMTP_IMPLICIT_TLS", false), "use implicit TLS (port 465) instead of STARTTLS [IDENTITY_SMTP_IMPLICIT_TLS]")
	fs.DurationVar(&c.CleanupInterval, "cleanup-interval", envDuration("IDENTITY_CLEANUP_INTERVAL", 15*time.Minute), "interval to delete expired tokens [IDENTITY_CLEANUP_INTERVAL]")
	fs.StringVar(&c.LogLevel, "log-level", env("IDENTITY_LOG_LEVEL", "info"), "debug, info, warn or error [IDENTITY_LOG_LEVEL]")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if c.SessionKey != "" && len(c.SessionKey) < 32 {
		return errors.New("the session key must have at least 32 characters")
	}
	if (c.AdminClientId == "") != (c.AdminClientSecret == "") {
		return errors.New("the admin client id and secret must be set together")
	}
	if c.AdminClientSecret != "" && (len(c.AdminClientSecret) < 16 || len(c.AdminClientSecret) > 72) {
		return errors.New("the admin client secret must have between 16 and 72 characters")
	}
	switch c.DatabaseDriver {
	case "memory":
	case "sqlite", "postgres", "mysql", "mongo":
		if c.DatabaseDSN == "" {
			return fmt.Errorf("a database connection string is required for %s", c.DatabaseDriver)
		}
	default:
		return fmt.Errorf("unsupported database driver %q", c.DatabaseDriver)
	}
	switch strings.ToLower(c.Router) {
	case "std", "chi", "gin", "httprouter", "gorillamux", "echo":
	default:
		return fmt.Errorf("unsupported router %q", c.Router)
	}
	return nil
}
