package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

type tokenContextKey struct{}

// TokenInfo describes the validated access token of a request.
type TokenInfo struct {
	Token  *identity.AccessToken
	Client *identity.Client
	// User is nil for client credentials tokens.
	User *identity.User
}

// TokenFromContext returns the access token validated by the bearer middleware.
func TokenFromContext(ctx context.Context) (*TokenInfo, bool) {
	info, ok := ctx.Value(tokenContextKey{}).(*TokenInfo)
	return info, ok
}

// ValidateAccessToken checks the access token and returns its information.
func (s *Server) ValidateAccessToken(ctx context.Context, token string) (*TokenInfo, error) {
	accessToken, err := s.opts.Store.GetAccessTokenByHash(ctx, security.HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, NewError(ErrorInvalidToken, "the access token is invalid")
	}
	if err != nil {
		return nil, err
	}
	if accessToken.HasExpired(s.now()) {
		return nil, NewError(ErrorInvalidToken, "the access token has expired")
	}
	client, err := s.opts.Store.GetClientById(ctx, accessToken.ClientId)
	if errors.Is(err, store.ErrNotFound) || err == nil && !client.Enabled {
		return nil, NewError(ErrorInvalidToken, "the client of the access token is not active")
	}
	if err != nil {
		return nil, err
	}
	info := &TokenInfo{Token: accessToken, Client: client}
	if accessToken.UserId != "" {
		user, err := s.opts.Store.GetUserById(ctx, accessToken.UserId)
		if errors.Is(err, store.ErrNotFound) || err == nil && s.opts.Accounts.CanSignIn(user) != nil {
			return nil, NewError(ErrorInvalidToken, "the resource owner of the access token is not active")
		}
		if err != nil {
			return nil, err
		}
		info.User = user
	}
	return info, nil
}

// RequireBearer returns a middleware that protects a resource with a bearer token (RFC 6750).
// The token must have all the given scopes.
func (s *Server) RequireBearer(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="identity"`)
				WriteJSON(w, http.StatusUnauthorized, NewError(ErrorInvalidToken, "an access token is required"))
				return
			}
			scheme, token, ok := strings.Cut(header, " ")
			if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
				writeBearerError(w, NewError(ErrorInvalidRequest, "the authorization header is malformed"), nil)
				return
			}
			info, err := s.ValidateAccessToken(r.Context(), strings.TrimSpace(token))
			if err != nil {
				writeBearerError(w, s.bearerError(r.Context(), err), nil)
				return
			}
			for _, scope := range scopes {
				if !identity.HasScope(info.Token.Scopes, scope) {
					writeBearerError(w, NewError(ErrorInsufficientScope, "the access token doesn't have the required scope"), scopes)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenContextKey{}, info)))
		})
	}
}

func (s *Server) bearerError(ctx context.Context, err error) *Error {
	var oauthErr *Error
	if errors.As(err, &oauthErr) {
		return oauthErr
	}
	return s.serverError(ctx, "failed to validate access token", err)
}

func writeBearerError(w http.ResponseWriter, err *Error, scopes []string) {
	challenge := `Bearer realm="identity", error="` + err.Code + `"`
	if err.Description != "" {
		challenge += `, error_description="` + err.Description + `"`
	}
	if len(scopes) > 0 {
		challenge += `, scope="` + identity.FormatScope(scopes) + `"`
	}
	if err.Code != ErrorServerError {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	WriteJSON(w, err.Status, err)
}
