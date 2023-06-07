package oauth

import (
	"context"
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

type OAuthService interface {
	// Client store
	GetClientByClientId(ctx context.Context, clientId string) (*Client, error)

	// Client secret hasher
	VerifyClientSecret(ctx context.Context, client *Client, clientSecret string) error

	// User store
	GetUserById(ctx context.Context, id string) (*User, error)
	GetUserByUserName(ctx context.Context, username string) (*User, error)

	// User password hasher
	VerifyUserPassword(ctx context.Context, user *User, password string) error

	// Access token store
	GenerateAccessToken(ctx context.Context, client *Client, user *User, scopes []string) (*AccessToken, error)
	GetAccessTokenById(ctx context.Context, id string) (*AccessToken, error)
	CreateAccessToken(ctx context.Context, accessToken *AccessToken) (*AccessToken, error)
	DeleteAccessToken(ctx context.Context, id string) error

	// Refresh token store
	GenerateRefreshToken(ctx context.Context, client *Client, accessToken *AccessToken) (*RefreshToken, error)
	GetRefreshTokenByToken(ctx context.Context, token string) (*RefreshToken, error)
	CreateRefreshToken(ctx context.Context, refreshToken *RefreshToken) (*RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, id string, refreshToken *RefreshToken) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, id string) error

	// Authorization code store
	GetAuthorizationCodeByCode(ctx context.Context, code string) (*AuthorizationCode, error)
	CreateAuthorizationCode(ctx context.Context, authorizationCode *AuthorizationCode) (*AuthorizationCode, error)
	DeleteAuthorizationCode(ctx context.Context, id string) error
}

type ClientStore interface {
	GetClientByClientId(ctx context.Context, clientId string) (*Client, error)
}

type UserStore interface {
	GetUserById(ctx context.Context, id string) (*User, error)
	GetUserByUserName(ctx context.Context, username string) (*User, error)
}

type AccessTokenStore interface {
	GetAccessTokenById(ctx context.Context, id string) (*AccessToken, error)
	CreateAccessToken(ctx context.Context, accessToken *AccessToken) (*AccessToken, error)
	DeleteAccessToken(ctx context.Context, id string) error
}

type RefreshTokenStore interface {
	GetRefreshTokenByToken(ctx context.Context, token string) (*RefreshToken, error)
	CreateRefreshToken(ctx context.Context, refreshToken *RefreshToken) (*RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, id string, refreshToken *RefreshToken) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, id string) error
}

type AuthorizationCodeStore interface {
	GetAuthorizationCodeByCode(ctx context.Context, code string) (*AuthorizationCode, error)
	CreateAuthorizationCode(ctx context.Context, authorizationCode *AuthorizationCode) (*AuthorizationCode, error)
	DeleteAuthorizationCode(ctx context.Context, id string) error
}

type SecretHasher interface {
	HashSecret(secret string) (string, error)
	VerifySecret(hash string, secret string) error
}

type TokenGenerator interface {
	GenerateAccessToken(ctx context.Context, client *Client, user *User, scopes []string) (*AccessToken, error)
	GenerateRefreshToken(ctx context.Context, client *Client, accessToken *AccessToken) (*RefreshToken, error)
}

type oAuthService struct {
}
