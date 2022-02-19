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
	ErrClientNotCreated error = errors.New("failed to create record")
	ErrClientNotUpdated error = errors.New("failed to update record")
	ErrClientNotDeleted error = errors.New("failed to delete record")
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
	ClientId               string
	ClientSecret           string
	RedirectUris           []string
	AllowedScopes          []string
	RefreshTokenUsage      RefreshTokenUsage
	RefreshTokenExpiration RefreshTokenExpirationType
	RefreshTokenLifetime   time.Duration
}

type ClientPage struct {
	PageIndex int
	PageSize  int
	Count     int
	Items     []*Client
}

type ClientSearch struct {
}

func (c *Client) SetDefaults() {
	c.RefreshTokenExpiration = SlidingRefreshTokenExpiration
	c.RefreshTokenLifetime = (15 * 24 * time.Hour)
	c.RefreshTokenUsage = ReUseRefreshTokenUsage
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
