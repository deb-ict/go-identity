package identity

import (
	"context"
	"errors"
	"time"
)

type RefreshTokenExpirationType string
type RefreshTokenUsage string

const (
	AbsoluteRefreshTokenExpiration RefreshTokenExpirationType = "absolute"
	SlidingRefreshTokenExpiration  RefreshTokenExpirationType = "sliding"
	ReUseRefreshTokenUsage         RefreshTokenUsage          = "reuse"
	OneTimeRefreshTokenUsage       RefreshTokenUsage          = "onetime"
)

var (
	ErrClientNotFound   error = errors.New("client not found")
	ErrClientNotCreated error = errors.New("client not created")
	ErrClientNotUpdated error = errors.New("client not updated")
	ErrClientNotDeleted error = errors.New("client not deleted")
)

type ClientStore interface {
	GetClients(ctx context.Context, search ClientSearch, pageIndex int, pageSize int) (*ClientPage, error)
	GetClientById(ctx context.Context, id string) (*Client, error)
	GetClientByClientId(ctx context.Context, clientId string) (*Client, error)
	CreateClient(ctx context.Context, client *Client) (string, error)
	UpdateClient(ctx context.Context, id string, client *Client) error
	DeleteClient(ctx context.Context, id string) error
}

type Client struct {
	Id                     string                     `json:"id"`
	ClientId               string                     `json:"client_id"`
	ClientSecret           string                     `json:"client_secret"`
	RedirectUris           []string                   `json:"redirect_uris"`
	AllowedScopes          []string                   `json:"allowed_scopes"`
	RefreshTokenUsage      RefreshTokenUsage          `json:"refresh_token_usage"`
	RefreshTokenExpiration RefreshTokenExpirationType `json:"refresh_token_expiration"`
	RefreshTokenLifetime   time.Duration              `json:"refresh_token_lifetime"`
}

type ClientPage struct {
	PageIndex int       `json:"page_index"`
	PageSize  int       `json:"page_size"`
	Count     int       `json:"count"`
	Items     []*Client `json:"items"`
}

type ClientSearch struct {
}

func (c *Client) SetDefaults() {
	c.RefreshTokenExpiration = SlidingRefreshTokenExpiration
	c.RefreshTokenUsage = ReUseRefreshTokenUsage
	c.RefreshTokenLifetime = (15 * 24 * time.Hour)
}

func (c *Client) ScopeAllowed(scope string) bool {
	for _, allowed := range c.AllowedScopes {
		if allowed == scope {
			return true
		}
	}
	return false
}

func (c *Client) ScopesAllowed(scopes []string) bool {
	for _, scope := range scopes {
		if !c.ScopeAllowed(scope) {
			return false
		}
	}
	return true
}
