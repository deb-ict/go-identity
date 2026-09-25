package oauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

const (
	TokenTypeHintAccessToken  = "access_token"
	TokenTypeHintRefreshToken = "refresh_token"
)

// HandleRevoke is the token revocation endpoint (RFC 7009).
//
// Revoking a refresh token also revokes its access token. The endpoint responds with 200 for
// invalid tokens and for tokens of other clients, which are left untouched.
func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	form, err := parsePostForm(w, r)
	if err != nil {
		WriteError(w, err)
		return
	}
	client, err := s.AuthenticateClient(r, form)
	if err != nil {
		WriteError(w, err)
		return
	}
	token, err := RequiredParam(form, "token")
	if err != nil {
		WriteError(w, err)
		return
	}
	hint, err := Param(form, "token_type_hint")
	if err != nil {
		WriteError(w, err)
		return
	}
	if revokeErr := s.revoke(r.Context(), client, token, hint); revokeErr != nil {
		WriteError(w, s.serverError(r.Context(), "failed to revoke token", revokeErr))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) revoke(ctx context.Context, client *identity.Client, token string, hint string) error {
	hash := security.HashToken(token)
	lookups := []func() (bool, error){
		func() (bool, error) {
			accessToken, err := s.opts.Store.GetAccessTokenByHash(ctx, hash)
			if errors.Is(err, store.ErrNotFound) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if accessToken.ClientId == client.Id {
				return true, ignoreNotFound(s.opts.Store.DeleteAccessToken(ctx, accessToken.Id))
			}
			return true, nil
		},
		func() (bool, error) {
			refreshToken, err := s.opts.Store.GetRefreshTokenByHash(ctx, hash)
			if errors.Is(err, store.ErrNotFound) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if refreshToken.ClientId == client.Id {
				if err := ignoreNotFound(s.opts.Store.DeleteRefreshToken(ctx, refreshToken.Id)); err != nil {
					return true, err
				}
				if refreshToken.AccessTokenId != "" {
					return true, ignoreNotFound(s.opts.Store.DeleteAccessToken(ctx, refreshToken.AccessTokenId))
				}
			}
			return true, nil
		},
	}
	if hint == TokenTypeHintRefreshToken {
		lookups[0], lookups[1] = lookups[1], lookups[0]
	}
	for _, lookup := range lookups {
		found, err := lookup()
		if found || err != nil {
			return err
		}
	}
	return nil
}

func ignoreNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// IntrospectionResponse is the token introspection response (RFC 7662 section 2.2).
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientId  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Issuer    string `json:"iss,omitempty"`
}

// HandleIntrospect is the token introspection endpoint (RFC 7662). Only confidential clients
// (e.g. resource servers) may introspect tokens.
func (s *Server) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	form, err := parsePostForm(w, r)
	if err != nil {
		WriteError(w, err)
		return
	}
	client, err := s.AuthenticateClient(r, form)
	if err != nil {
		WriteError(w, err)
		return
	}
	if client.IsPublic() {
		WriteError(w, NewError(ErrorInvalidClient, "public clients can't introspect tokens"))
		return
	}
	token, err := RequiredParam(form, "token")
	if err != nil {
		WriteError(w, err)
		return
	}
	hint, err := Param(form, "token_type_hint")
	if err != nil {
		WriteError(w, err)
		return
	}
	response, introspectErr := s.Introspect(r.Context(), token, hint)
	if introspectErr != nil {
		WriteError(w, s.serverError(r.Context(), "failed to introspect token", introspectErr))
		return
	}
	WriteJSON(w, http.StatusOK, response)
}

// Introspect returns the state of an access or refresh token.
func (s *Server) Introspect(ctx context.Context, token string, hint string) (*IntrospectionResponse, error) {
	hash := security.HashToken(token)
	now := s.now()
	inactive := &IntrospectionResponse{Active: false}

	type found struct {
		tokenType string
		clientId  string
		userId    string
		scopes    []string
		createdAt int64
		expiresAt int64
		expired   bool
	}
	lookups := []func() (*found, error){
		func() (*found, error) {
			t, err := s.opts.Store.GetAccessTokenByHash(ctx, hash)
			if err != nil {
				return nil, err
			}
			return &found{TokenTypeBearer, t.ClientId, t.UserId, t.Scopes, t.CreatedAt.Unix(), t.ExpiresAt.Unix(), t.HasExpired(now)}, nil
		},
		func() (*found, error) {
			t, err := s.opts.Store.GetRefreshTokenByHash(ctx, hash)
			if err != nil {
				return nil, err
			}
			return &found{TokenTypeHintRefreshToken, t.ClientId, t.UserId, t.Scopes, t.CreatedAt.Unix(), t.ExpiresAt.Unix(), t.HasExpired(now)}, nil
		},
	}
	if hint == TokenTypeHintRefreshToken {
		lookups[0], lookups[1] = lookups[1], lookups[0]
	}

	var f *found
	for _, lookup := range lookups {
		var err error
		f, err = lookup()
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	if f == nil || f.expired {
		return inactive, nil
	}

	client, err := s.opts.Store.GetClientById(ctx, f.clientId)
	if errors.Is(err, store.ErrNotFound) {
		return inactive, nil
	}
	if err != nil {
		return nil, err
	}
	if !client.Enabled {
		return inactive, nil
	}
	response := &IntrospectionResponse{
		Active:    true,
		Scope:     identity.FormatScope(f.scopes),
		ClientId:  client.ClientId,
		TokenType: f.tokenType,
		ExpiresAt: f.expiresAt,
		IssuedAt:  f.createdAt,
		Issuer:    s.opts.Issuer,
	}
	if f.userId != "" {
		user, err := s.opts.Store.GetUserById(ctx, f.userId)
		if errors.Is(err, store.ErrNotFound) {
			return inactive, nil
		}
		if err != nil {
			return nil, err
		}
		if s.opts.Accounts.CanSignIn(user) != nil {
			return inactive, nil
		}
		response.Subject = user.Id
		response.Username = user.Username
	}
	return response, nil
}
