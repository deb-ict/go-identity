package api

import (
	"net/http"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

// Client is the API representation of a client. Lifetimes are in seconds.
type Client struct {
	Id                        string                              `json:"id"`
	ClientId                  string                              `json:"client_id"`
	Name                      string                              `json:"name"`
	Description               string                              `json:"description"`
	Type                      identity.ClientType                 `json:"type"`
	HasSecret                 bool                                `json:"has_secret"`
	RedirectUris              []string                            `json:"redirect_uris"`
	AllowedScopes             []string                            `json:"allowed_scopes"`
	DefaultScopes             []string                            `json:"default_scopes"`
	GrantTypes                []identity.GrantType                `json:"grant_types"`
	RequireConsent            bool                                `json:"require_consent"`
	RequirePkce               bool                                `json:"require_pkce"`
	Enabled                   bool                                `json:"enabled"`
	AccessTokenLifetime       int64                               `json:"access_token_lifetime"`
	AuthorizationCodeLifetime int64                               `json:"authorization_code_lifetime"`
	RefreshTokenLifetime      int64                               `json:"refresh_token_lifetime"`
	RefreshTokenUsage         identity.RefreshTokenUsage          `json:"refresh_token_usage"`
	RefreshTokenExpiration    identity.RefreshTokenExpirationType `json:"refresh_token_expiration"`
	CreatedAt                 time.Time                           `json:"created_at"`
	UpdatedAt                 time.Time                           `json:"updated_at"`
}

// ClientRequest creates or updates a client. Omitted lifetimes and policies use the defaults.
type ClientRequest struct {
	ClientId                  string                              `json:"client_id"`
	Name                      string                              `json:"name"`
	Description               string                              `json:"description"`
	Type                      identity.ClientType                 `json:"type"`
	RedirectUris              []string                            `json:"redirect_uris"`
	AllowedScopes             []string                            `json:"allowed_scopes"`
	DefaultScopes             []string                            `json:"default_scopes"`
	GrantTypes                []identity.GrantType                `json:"grant_types"`
	RequireConsent            bool                                `json:"require_consent"`
	RequirePkce               bool                                `json:"require_pkce"`
	Enabled                   *bool                               `json:"enabled"`
	AccessTokenLifetime       int64                               `json:"access_token_lifetime"`
	AuthorizationCodeLifetime int64                               `json:"authorization_code_lifetime"`
	RefreshTokenLifetime      int64                               `json:"refresh_token_lifetime"`
	RefreshTokenUsage         identity.RefreshTokenUsage          `json:"refresh_token_usage"`
	RefreshTokenExpiration    identity.RefreshTokenExpirationType `json:"refresh_token_expiration"`
}

// ClientWithSecret is returned when a secret is generated. The secret is only shown once.
type ClientWithSecret struct {
	*Client
	ClientSecret string `json:"client_secret,omitempty"`
}

// SecretResponse is returned when a client secret is regenerated.
type SecretResponse struct {
	ClientSecret string `json:"client_secret"`
}

func toClient(c *identity.Client) *Client {
	return &Client{
		Id:                        c.Id,
		ClientId:                  c.ClientId,
		Name:                      c.Name,
		Description:               c.Description,
		Type:                      c.Type,
		HasSecret:                 c.SecretHash != "",
		RedirectUris:              nonNil(c.RedirectUris),
		AllowedScopes:             nonNil(c.AllowedScopes),
		DefaultScopes:             nonNil(c.DefaultScopes),
		GrantTypes:                nonNil(c.AllowedGrantTypes),
		RequireConsent:            c.RequireConsent,
		RequirePkce:               c.RequirePkce,
		Enabled:                   c.Enabled,
		AccessTokenLifetime:       seconds(c.AccessTokenLifetime),
		AuthorizationCodeLifetime: seconds(c.AuthorizationCodeLifetime),
		RefreshTokenLifetime:      seconds(c.RefreshTokenLifetime),
		RefreshTokenUsage:         c.RefreshTokenUsage,
		RefreshTokenExpiration:    c.RefreshTokenExpiration,
		CreatedAt:                 c.CreatedAt,
		UpdatedAt:                 c.UpdatedAt,
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// apply copies the request to the client and validates the result.
func (req *ClientRequest) apply(c *identity.Client) error {
	c.ClientId = req.ClientId
	c.Name = req.Name
	c.Description = req.Description
	c.Type = req.Type
	c.RedirectUris = req.RedirectUris
	c.AllowedScopes = req.AllowedScopes
	c.DefaultScopes = req.DefaultScopes
	c.AllowedGrantTypes = req.GrantTypes
	c.RequireConsent = req.RequireConsent
	c.RequirePkce = req.RequirePkce
	if req.Enabled != nil {
		c.Enabled = *req.Enabled
	}
	c.AccessTokenLifetime = duration(req.AccessTokenLifetime)
	c.AuthorizationCodeLifetime = duration(req.AuthorizationCodeLifetime)
	c.RefreshTokenLifetime = duration(req.RefreshTokenLifetime)
	c.RefreshTokenUsage = req.RefreshTokenUsage
	c.RefreshTokenExpiration = req.RefreshTokenExpiration
	c.EnsureDefaults()
	if c.AuthorizationCodeLifetime > 10*time.Minute {
		// RFC 6749 section 4.1.2: a maximum lifetime of 10 minutes is recommended
		return identity.NewValidationError("authorization_code_lifetime", "must not exceed 600 seconds")
	}
	return c.Validate()
}

func (a *API) listClients(w http.ResponseWriter, r *http.Request) {
	opts, ok := listOptions(w, r)
	if !ok {
		return
	}
	clients, total, err := a.opts.Store.ListClients(r.Context(), opts)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	respondList(w, clients, total, opts, toClient)
}

func (a *API) getClient(w http.ResponseWriter, r *http.Request) {
	client, err := a.opts.Store.GetClientById(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toClient(client))
}

func (a *API) createClient(w http.ResponseWriter, r *http.Request) {
	req := &ClientRequest{}
	if !decode(w, r, req) {
		return
	}
	now := a.now()
	client := &identity.Client{Id: security.NewId(), Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := req.apply(client); err != nil {
		a.handleError(w, r, err)
		return
	}
	secret := ""
	if !client.IsPublic() {
		var err error
		secret = security.NewToken()
		client.SecretHash, err = a.opts.Hasher.Hash(secret)
		if err != nil {
			a.handleError(w, r, err)
			return
		}
	}
	if err := a.opts.Store.CreateClient(r.Context(), client); err != nil {
		a.handleError(w, r, err)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+client.Id)
	writeJSON(w, http.StatusCreated, &ClientWithSecret{Client: toClient(client), ClientSecret: secret})
}

func (a *API) updateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := &ClientRequest{}
	if !decode(w, r, req) {
		return
	}
	client, err := a.opts.Store.GetClientById(ctx, router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	wasEnabled := client.Enabled
	if err := req.apply(client); err != nil {
		a.handleError(w, r, err)
		return
	}
	if client.IsPublic() {
		client.SecretHash = ""
	}
	client.UpdatedAt = a.now()
	if err := a.opts.Store.UpdateClient(ctx, client); err != nil {
		a.handleError(w, r, err)
		return
	}
	if wasEnabled && !client.Enabled {
		if err := a.revokeTokens(r, store.TokenFilter{ClientId: client.Id}); err != nil {
			a.handleError(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, toClient(client))
}

func (a *API) deleteClient(w http.ResponseWriter, r *http.Request) {
	id := router.Param(r, "id")
	if err := a.opts.Store.DeleteClient(r.Context(), id); err != nil {
		a.handleError(w, r, err)
		return
	}
	if err := a.revokeTokens(r, store.TokenFilter{ClientId: id}); err != nil {
		a.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) regenerateClientSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	client, err := a.opts.Store.GetClientById(ctx, router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	if client.IsPublic() {
		writeError(w, http.StatusBadRequest, "invalid_request", "public clients don't have a secret")
		return
	}
	secret := security.NewToken()
	client.SecretHash, err = a.opts.Hasher.Hash(secret)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	client.UpdatedAt = a.now()
	if err := a.opts.Store.UpdateClient(ctx, client); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, &SecretResponse{ClientSecret: secret})
}

func (a *API) revokeTokens(r *http.Request, filter store.TokenFilter) error {
	if _, err := a.opts.Store.DeleteRefreshTokens(r.Context(), filter); err != nil {
		return err
	}
	_, err := a.opts.Store.DeleteAccessTokens(r.Context(), filter)
	return err
}
