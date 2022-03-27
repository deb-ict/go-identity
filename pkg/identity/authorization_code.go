package identity

import (
	"context"
	"time"
)

type AuthorizationCodeStore interface {
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) (string, error)
	DeleteAuthorizationCode(ctx context.Context, code string) error
}

type AuthorizationCode struct {
	ClientId        string
	RedirectUri     string
	Code            string
	RequestedScopes []string
	Lifetime        time.Duration
}
