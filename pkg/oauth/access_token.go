package oauth

import (
	"time"
)

type AccessToken struct {
	Id          string
	ClientId    string
	UserId      string
	TokenType   string
	AccessToken string
	Scopes      []string
	CreatedAt   time.Time
	Lifetime    time.Duration
}

func (token *AccessToken) HasExpired() bool {
	return token.CreatedAt.Add(token.Lifetime).Before(time.Now().UTC())
}
