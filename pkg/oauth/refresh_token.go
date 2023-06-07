package oauth

import (
	"time"
)

type RefreshToken struct {
	Id              string
	ClientId        string
	UserId          string
	AccessTokenId   string
	TokenExpiration RefreshTokenExpirationType
	TokenUsage      RefreshTokenUsage
	Scopes          []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Lifetime        time.Duration
}

func (token *RefreshToken) HasExpired() bool {
	return token.UpdatedAt.Add(token.Lifetime).Before(time.Now().UTC())
}

func (token *RefreshToken) ValidateScope(scope string) bool {
	for _, allowedScope := range token.Scopes {
		if allowedScope == scope {
			return true
		}
	}
	return false
}

func (token *RefreshToken) ValidateScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !token.ValidateScope(scope) {
			return false
		}
	}
	return true
}
