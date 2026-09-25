// Package api implements the JSON management API of the identity server: clients, users,
// access tokens and refresh tokens.
//
// All endpoints require a bearer access token with the admin scope (see server.Config.AdminScope).
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/deb-ict/go-identity/pkg/account"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/oauth"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

// PathPrefix is the path prefix of the API, relative to the base path.
const PathPrefix = "/api"

// Options configures the management API.
type Options struct {
	Store    store.Store
	Accounts *account.Service
	// Hasher hashes client secrets.
	Hasher security.PasswordHasher
	// Middleware protects all endpoints, e.g. oauth.Server.RequireBearer("identity.admin").
	Middleware []router.Middleware
	Now        func() time.Time
	Logger     *slog.Logger
}

// API serves the management endpoints.
type API struct {
	opts Options
}

// New creates the management API.
func New(opts Options) (*API, error) {
	if opts.Store == nil || opts.Accounts == nil {
		return nil, errors.New("api: store and accounts are required")
	}
	if opts.Hasher == nil {
		opts.Hasher = security.NewBcryptHasher(0)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &API{opts: opts}, nil
}

// RegisterRoutes registers the API endpoints below /api. The router must already apply the base path.
func (a *API) RegisterRoutes(r router.Router) {
	r = router.WithPrefix(router.WithMiddleware(r, a.opts.Middleware...), PathPrefix)
	handle := func(method string, pattern string, h http.HandlerFunc) {
		r.Handle(method, pattern, h)
	}

	handle(http.MethodGet, "/clients", a.listClients)
	handle(http.MethodPost, "/clients", a.createClient)
	handle(http.MethodGet, "/clients/{id}", a.getClient)
	handle(http.MethodPut, "/clients/{id}", a.updateClient)
	handle(http.MethodDelete, "/clients/{id}", a.deleteClient)
	handle(http.MethodPost, "/clients/{id}/secret", a.regenerateClientSecret)

	handle(http.MethodGet, "/users", a.listUsers)
	handle(http.MethodPost, "/users", a.createUser)
	handle(http.MethodGet, "/users/{id}", a.getUser)
	handle(http.MethodPut, "/users/{id}", a.updateUser)
	handle(http.MethodDelete, "/users/{id}", a.deleteUser)
	handle(http.MethodPost, "/users/{id}/password", a.setUserPassword)
	handle(http.MethodPost, "/users/{id}/unlock", a.unlockUser)
	handle(http.MethodPost, "/users/{id}/activation", a.sendUserActivation)
	handle(http.MethodPost, "/users/{id}/password-reset", a.sendUserPasswordReset)
	handle(http.MethodDelete, "/users/{id}/tokens", a.revokeUserTokens)

	handle(http.MethodGet, "/tokens", a.listAccessTokens)
	handle(http.MethodDelete, "/tokens", a.deleteAccessTokens)
	handle(http.MethodGet, "/tokens/{id}", a.getAccessToken)
	handle(http.MethodDelete, "/tokens/{id}", a.deleteAccessToken)

	handle(http.MethodGet, "/refresh-tokens", a.listRefreshTokens)
	handle(http.MethodDelete, "/refresh-tokens", a.deleteRefreshTokens)
	handle(http.MethodGet, "/refresh-tokens/{id}", a.getRefreshToken)
	handle(http.MethodDelete, "/refresh-tokens/{id}", a.deleteRefreshToken)
}

func (a *API) now() time.Time {
	return a.opts.Now().UTC().Truncate(time.Millisecond)
}

// Error is the error response of the API.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	Field       string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	oauth.WriteJSON(w, status, value)
}

func writeError(w http.ResponseWriter, status int, code string, description string) {
	writeJSON(w, status, &Error{Code: code, Description: description})
}

func (a *API) handleError(w http.ResponseWriter, r *http.Request, err error) {
	var validation *identity.ValidationError
	switch {
	case errors.As(err, &validation):
		writeJSON(w, http.StatusBadRequest, &Error{Code: "validation_failed", Description: validation.Error(), Field: validation.Field})
	case errors.Is(err, store.ErrNotFound), errors.Is(err, account.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "the resource doesn't exist")
	case errors.Is(err, store.ErrDuplicate), errors.Is(err, account.ErrUserExists):
		writeError(w, http.StatusConflict, "conflict", "a resource with the same unique value already exists")
	default:
		a.opts.Logger.ErrorContext(r.Context(), "api request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "an unexpected error occurred")
	}
}

// decode reads a JSON request body into the value. Unknown fields are rejected.
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "the content type must be application/json")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the request body is invalid: "+err.Error())
		return false
	}
	if _, err := decoder.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "the request body must contain a single JSON object")
		return false
	}
	return true
}

// ListResponse is a page of a list.
type ListResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

func listOptions(w http.ResponseWriter, r *http.Request) (store.ListOptions, bool) {
	opts := store.ListOptions{}
	q := r.URL.Query()
	for name, target := range map[string]*int{"offset": &opts.Offset, "limit": &opts.Limit} {
		if v := q.Get(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				writeError(w, http.StatusBadRequest, "invalid_request", "the "+name+" parameter must be a positive number")
				return opts, false
			}
			*target = n
		}
	}
	return opts.Normalize(), true
}

func respondList[S any, T any](w http.ResponseWriter, items []S, total int, opts store.ListOptions, convert func(S) T) {
	result := make([]T, 0, len(items))
	for _, item := range items {
		result = append(result, convert(item))
	}
	writeJSON(w, http.StatusOK, &ListResponse[T]{Items: result, Total: total, Offset: opts.Offset, Limit: opts.Limit})
}

func seconds(d time.Duration) int64 {
	return int64(d / time.Second)
}

func duration(seconds int64) time.Duration {
	return time.Duration(seconds) * time.Second
}
