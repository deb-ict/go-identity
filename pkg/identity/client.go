package identity

import (
	"net/url"
	"strings"
	"time"
)

// ClientType is the OAuth 2.0 client type (RFC 6749 section 2.1).
type ClientType string

// RefreshTokenExpirationType defines how the lifetime of a refresh token is calculated.
type RefreshTokenExpirationType string

// RefreshTokenUsage defines whether a refresh token can be used more than once.
type RefreshTokenUsage string

// ResponseType is an authorization endpoint response type (RFC 6749 section 3.1.1).
type ResponseType string

// GrantType is an authorization grant type (RFC 6749 section 1.3).
type GrantType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"

	RefreshTokenExpirationAbsolute RefreshTokenExpirationType = "absolute"
	RefreshTokenExpirationSliding  RefreshTokenExpirationType = "sliding"

	RefreshTokenUsageReUse   RefreshTokenUsage = "reuse"
	RefreshTokenUsageOneTime RefreshTokenUsage = "onetime"

	ResponseTypeCode  ResponseType = "code"
	ResponseTypeToken ResponseType = "token"

	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeImplicit          GrantType = "implicit"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypePassword          GrantType = "password"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

const (
	DefaultAccessTokenLifetime       = time.Hour
	DefaultAuthorizationCodeLifetime = 5 * time.Minute
	DefaultRefreshTokenLifetime      = 30 * 24 * time.Hour
)

// Client is an OAuth 2.0 client registration (RFC 6749 section 2).
type Client struct {
	Id                        string
	ClientId                  string
	Name                      string
	Description               string
	Type                      ClientType
	SecretHash                string
	RedirectUris              []string
	AllowedScopes             []string
	DefaultScopes             []string
	AllowedGrantTypes         []GrantType
	RequireConsent            bool
	RequirePkce               bool
	Enabled                   bool
	AccessTokenLifetime       time.Duration
	AuthorizationCodeLifetime time.Duration
	RefreshTokenUsage         RefreshTokenUsage
	RefreshTokenExpiration    RefreshTokenExpirationType
	RefreshTokenLifetime      time.Duration
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

// EnsureDefaults fills in the default values for unset settings.
func (c *Client) EnsureDefaults() {
	if c.Type == "" {
		c.Type = ClientTypeConfidential
	}
	if c.RefreshTokenUsage == "" {
		c.RefreshTokenUsage = RefreshTokenUsageReUse
	}
	if c.RefreshTokenExpiration == "" {
		c.RefreshTokenExpiration = RefreshTokenExpirationSliding
	}
	if c.AccessTokenLifetime <= 0 {
		c.AccessTokenLifetime = DefaultAccessTokenLifetime
	}
	if c.AuthorizationCodeLifetime <= 0 {
		c.AuthorizationCodeLifetime = DefaultAuthorizationCodeLifetime
	}
	if c.RefreshTokenLifetime <= 0 {
		c.RefreshTokenLifetime = DefaultRefreshTokenLifetime
	}
	if c.RedirectUris == nil {
		c.RedirectUris = []string{}
	}
	if c.AllowedScopes == nil {
		c.AllowedScopes = []string{}
	}
	if c.DefaultScopes == nil {
		c.DefaultScopes = []string{}
	}
	if c.AllowedGrantTypes == nil {
		c.AllowedGrantTypes = []GrantType{}
	}
}

// Validate checks the client registration for consistency.
func (c *Client) Validate() error {
	if c.ClientId == "" {
		return NewValidationError("client_id", "is required")
	}
	if c.Type != ClientTypeConfidential && c.Type != ClientTypePublic {
		return NewValidationError("type", "must be 'confidential' or 'public'")
	}
	for _, uri := range c.RedirectUris {
		// RFC 6749 section 3.1.2: absolute URI without fragment
		u, err := url.Parse(uri)
		if err != nil || !u.IsAbs() || strings.Contains(uri, "#") {
			return NewValidationError("redirect_uris", "must be absolute URIs without a fragment")
		}
	}
	for _, scope := range append(append([]string{}, c.AllowedScopes...), c.DefaultScopes...) {
		if !IsValidScopeToken(scope) {
			return NewValidationError("scopes", "contains an invalid scope: "+scope)
		}
	}
	for _, scope := range c.DefaultScopes {
		if !c.ValidateScope(scope) {
			return NewValidationError("default_scopes", "must be a subset of allowed_scopes")
		}
	}
	for _, grantType := range c.AllowedGrantTypes {
		if grantType == "" {
			return NewValidationError("grant_types", "contains an empty grant type")
		}
		if grantType == GrantTypeClientCredentials && c.Type == ClientTypePublic {
			return NewValidationError("grant_types", "client_credentials is not allowed for public clients")
		}
	}
	if c.RefreshTokenUsage != RefreshTokenUsageReUse && c.RefreshTokenUsage != RefreshTokenUsageOneTime {
		return NewValidationError("refresh_token_usage", "must be 'reuse' or 'onetime'")
	}
	if c.RefreshTokenExpiration != RefreshTokenExpirationSliding && c.RefreshTokenExpiration != RefreshTokenExpirationAbsolute {
		return NewValidationError("refresh_token_expiration", "must be 'sliding' or 'absolute'")
	}
	return nil
}

// IsPublic returns true when the client can't keep a secret (RFC 6749 section 2.1).
func (c *Client) IsPublic() bool {
	return c.Type == ClientTypePublic
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

// ValidateRedirectUri uses simple string comparison (RFC 6749 section 3.1.2.3, RFC 3986 section 6.2.1).
func (c *Client) ValidateRedirectUri(uri string) bool {
	_, ok := c.MatchRedirectUri(uri)
	return ok
}

// MatchRedirectUri returns the registered redirection URI that is equal to the uri.
func (c *Client) MatchRedirectUri(uri string) (string, bool) {
	for _, redirectUri := range c.RedirectUris {
		if redirectUri == uri {
			return redirectUri, true
		}
	}
	return "", false
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
