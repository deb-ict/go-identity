package identity

import (
	"time"
)

type AccessToken struct {
	Id                   string
	ClientId             string
	UserId               string
	TokenType            string
	AccessToken          string
	RefreshToken         string
	Scopes               []string
	CreatedAt            time.Time
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
}

func (token *AccessToken) AccessTokenExpired() bool {
	return token.CreatedAt.Add(token.AccessTokenLifetime).Before(time.Now().UTC())
}

func (token *AccessToken) RefreshTokenExpired() bool {
	return token.CreatedAt.Add(token.RefreshTokenLifetime).Before(time.Now().UTC())
}
