package identity

import (
	"time"
)

type RefreshTokenExpirationType string
type RefreshTokenUsage string
type ResponseType string
type GrantType string

const (
	RefreshTokenExpirationAbsolute RefreshTokenExpirationType = "absolute"
	RefreshTokenExpirationSliding  RefreshTokenExpirationType = "sliding"
	RefreshTokenUsageReUse         RefreshTokenUsage          = "reuse"
	RefreshTokenUsageOneTime       RefreshTokenUsage          = "onetime"
	ResponseTypeCode               ResponseType               = "code"
	ResponseTypeToken              ResponseType               = "token"
	GrantTypeAuthorizationCode     GrantType                  = "authorization_code"
	GrantTypeClientCredentials     GrantType                  = "client_credentials"
	GrantTypePassword              GrantType                  = "password"
	GrantTypeRefreshToken          GrantType                  = "refresh_token"
)

type Client struct {
	Id                        string
	ClientId                  string
	ClientSecret              string
	ClientSecretRequired      bool
	RedirectUris              []string
	AllowedScopes             []string
	AllowedGrantTypes         []GrantType
	AccessTokenLifetime       time.Duration
	AuthorizationCodeLifetime time.Duration
	RefreshTokenUsage         RefreshTokenUsage
	RefreshTokenExpiration    RefreshTokenExpirationType
	RefreshTokenLifetime      time.Duration
}

func (c *Client) EnsureDefaults() {
	if c.RefreshTokenUsage == "" {
		c.RefreshTokenUsage = RefreshTokenUsageReUse
	}
	if c.RefreshTokenExpiration == "" {
		c.RefreshTokenExpiration = RefreshTokenExpirationSliding
	}
	if c.AccessTokenLifetime.Seconds() <= 0 {
		c.AccessTokenLifetime = 3600 * time.Second
	}
	if c.AuthorizationCodeLifetime.Seconds() <= 0 {
		c.AuthorizationCodeLifetime = 300 * time.Second
	}
	if c.RefreshTokenLifetime.Seconds() <= 0 {
		c.RefreshTokenLifetime = 720 * time.Hour // 30 days
	}
}

func (c *Client) AccessTokenLifetimeSeconds() int {
	return int(c.AccessTokenLifetime.Seconds())
}

func (c *Client) AuthorizationCodeLifetimeSeconds() int {
	return int(c.AuthorizationCodeLifetime.Seconds())
}

func (c *Client) RefreshTokenLifetimeSeconds() int {
	return int(c.RefreshTokenLifetime.Seconds())
}

func (c *Client) ValidateRedirectUri(uri string) bool {
	for _, redirectUri := range c.RedirectUris {
		if redirectUri == uri {
			return true
		}
	}
	return false
}

func (c *Client) ValidateScope(scope string) bool {
	for _, allowedScope := range c.AllowedScopes {
		if allowedScope == scope {
			return true
		}
	}
	return false
}

func (c *Client) ValidateScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !c.ValidateScope(scope) {
			return false
		}
	}
	return true
}

func (c *Client) ValidateGrantType(grantType GrantType) bool {
	for _, allowedGrantType := range c.AllowedGrantTypes {
		if allowedGrantType == grantType {
			return true
		}
	}
	return false
}
