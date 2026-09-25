package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/store"
)

// AccessToken is the API representation of an access token. The token value is never exposed.
// ClientId is the id of the client resource (not the OAuth client_id).
type AccessToken struct {
	Id                  string    `json:"id"`
	ClientId            string    `json:"client_id"`
	UserId              string    `json:"user_id,omitempty"`
	Scopes              []string  `json:"scopes"`
	AuthorizationCodeId string    `json:"authorization_code_id,omitempty"`
	Expired             bool      `json:"expired"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// RefreshToken is the API representation of a refresh token. The token value is never exposed.
type RefreshToken struct {
	Id                  string                              `json:"id"`
	ClientId            string                              `json:"client_id"`
	UserId              string                              `json:"user_id,omitempty"`
	AccessTokenId       string                              `json:"access_token_id,omitempty"`
	AuthorizationCodeId string                              `json:"authorization_code_id,omitempty"`
	Scopes              []string                            `json:"scopes"`
	Usage               identity.RefreshTokenUsage          `json:"usage"`
	Expiration          identity.RefreshTokenExpirationType `json:"expiration"`
	Expired             bool                                `json:"expired"`
	CreatedAt           time.Time                           `json:"created_at"`
	UpdatedAt           time.Time                           `json:"updated_at"`
	ExpiresAt           time.Time                           `json:"expires_at"`
}

// DeleteResponse reports the number of deleted resources.
type DeleteResponse struct {
	Deleted int `json:"deleted"`
}

func (a *API) toAccessToken(t *identity.AccessToken) *AccessToken {
	return &AccessToken{
		Id:                  t.Id,
		ClientId:            t.ClientId,
		UserId:              t.UserId,
		Scopes:              nonNil(t.Scopes),
		AuthorizationCodeId: t.AuthorizationCodeId,
		Expired:             t.HasExpired(a.now()),
		CreatedAt:           t.CreatedAt,
		ExpiresAt:           t.ExpiresAt,
	}
}

func (a *API) toRefreshToken(t *identity.RefreshToken) *RefreshToken {
	return &RefreshToken{
		Id:                  t.Id,
		ClientId:            t.ClientId,
		UserId:              t.UserId,
		AccessTokenId:       t.AccessTokenId,
		AuthorizationCodeId: t.AuthorizationCodeId,
		Scopes:              nonNil(t.Scopes),
		Usage:               t.TokenUsage,
		Expiration:          t.TokenExpiration,
		Expired:             t.HasExpired(a.now()),
		CreatedAt:           t.CreatedAt,
		UpdatedAt:           t.UpdatedAt,
		ExpiresAt:           t.ExpiresAt,
	}
}

// tokenFilter reads the client_id, user_id and expired query parameters.
// expired=true only matches expired tokens.
func (a *API) tokenFilter(r *http.Request) store.TokenFilter {
	q := r.URL.Query()
	filter := store.TokenFilter{ClientId: q.Get("client_id"), UserId: q.Get("user_id")}
	if q.Get("expired") == "true" {
		now := a.now()
		filter.ExpiredBefore = &now
	}
	return filter
}

func (a *API) listAccessTokens(w http.ResponseWriter, r *http.Request) {
	opts, ok := listOptions(w, r)
	if !ok {
		return
	}
	tokens, total, err := a.opts.Store.ListAccessTokens(r.Context(), a.tokenFilter(r), opts)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	respondList(w, tokens, total, opts, a.toAccessToken)
}

func (a *API) getAccessToken(w http.ResponseWriter, r *http.Request) {
	token, err := a.opts.Store.GetAccessTokenById(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.toAccessToken(token))
}

func (a *API) deleteAccessToken(w http.ResponseWriter, r *http.Request) {
	if err := a.opts.Store.DeleteAccessToken(r.Context(), router.Param(r, "id")); err != nil {
		a.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteAccessTokens(w http.ResponseWriter, r *http.Request) {
	filter := a.tokenFilter(r)
	if filter.IsEmpty() {
		writeError(w, http.StatusBadRequest, "invalid_request", "a client_id, user_id or expired filter is required")
		return
	}
	n, err := a.opts.Store.DeleteAccessTokens(r.Context(), filter)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, &DeleteResponse{Deleted: n})
}

func (a *API) listRefreshTokens(w http.ResponseWriter, r *http.Request) {
	opts, ok := listOptions(w, r)
	if !ok {
		return
	}
	tokens, total, err := a.opts.Store.ListRefreshTokens(r.Context(), a.tokenFilter(r), opts)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	respondList(w, tokens, total, opts, a.toRefreshToken)
}

func (a *API) getRefreshToken(w http.ResponseWriter, r *http.Request) {
	token, err := a.opts.Store.GetRefreshTokenById(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.toRefreshToken(token))
}

// deleteRefreshToken revokes the refresh token and its current access token.
func (a *API) deleteRefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token, err := a.opts.Store.GetRefreshTokenById(ctx, router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	if err := a.opts.Store.DeleteRefreshToken(ctx, token.Id); err != nil {
		a.handleError(w, r, err)
		return
	}
	if token.AccessTokenId != "" {
		if err := a.opts.Store.DeleteAccessToken(ctx, token.AccessTokenId); err != nil && !errors.Is(err, store.ErrNotFound) {
			a.handleError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteRefreshTokens(w http.ResponseWriter, r *http.Request) {
	filter := a.tokenFilter(r)
	if filter.IsEmpty() {
		writeError(w, http.StatusBadRequest, "invalid_request", "a client_id, user_id or expired filter is required")
		return
	}
	n, err := a.opts.Store.DeleteRefreshTokens(r.Context(), filter)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, &DeleteResponse{Deleted: n})
}
