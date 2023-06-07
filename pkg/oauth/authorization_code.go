package oauth

import (
	"time"
)

type AuthorizationCode struct {
	Id          string
	ClientId    string
	UserId      string
	Code        string
	Scopes      []string
	RedirectUri string
	CreatedAt   time.Time
	Lifetime    time.Duration
}

func (code *AuthorizationCode) Expired() bool {
	return code.CreatedAt.Add(code.Lifetime).Before(time.Now().UTC())
}

func (code *AuthorizationCode) ValidateRedirectUri(redirectUri string) bool {
	if redirectUri == "" {
		return true
	}
	return redirectUri == code.RedirectUri
}
