// Package store defines the persistence abstraction of the identity server.
//
// Implementations exist for memory (pkg/store/memory), SQL databases such as
// PostgreSQL, MySQL and SQLite (module store/sql) and MongoDB (module store/mongo).
// Every implementation must pass the conformance suite in pkg/store/storetest.
//
// Stores never generate identifiers: the caller sets the Id of new entities.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
)

var (
	// ErrNotFound is returned when the requested entity doesn't exist.
	ErrNotFound = errors.New("store: not found")
	// ErrDuplicate is returned when a unique constraint is violated (id, client id, username, email, token hash).
	ErrDuplicate = errors.New("store: duplicate")
	// ErrConflict is returned when a conditional update fails, e.g. an authorization code that was already consumed.
	ErrConflict = errors.New("store: conflict")
)

const (
	DefaultLimit = 50
	MaxLimit     = 500
)

// ListOptions controls pagination of list queries. Results are ordered by creation time, then id.
type ListOptions struct {
	Offset int
	Limit  int
}

// Normalize applies default and maximum values.
func (o ListOptions) Normalize() ListOptions {
	if o.Offset < 0 {
		o.Offset = 0
	}
	if o.Limit <= 0 {
		o.Limit = DefaultLimit
	}
	if o.Limit > MaxLimit {
		o.Limit = MaxLimit
	}
	return o
}

// UserFilter filters user list queries.
type UserFilter struct {
	// Search matches (case insensitive) a part of the username or email.
	Search string
}

// TokenFilter filters access and refresh token queries. Empty fields are ignored.
type TokenFilter struct {
	ClientId            string
	UserId              string
	AuthorizationCodeId string
	// ExpiredBefore matches tokens that expire at or before the given time.
	ExpiredBefore *time.Time
}

// IsEmpty returns true if no criteria are set.
func (f TokenFilter) IsEmpty() bool {
	return f.ClientId == "" && f.UserId == "" && f.AuthorizationCodeId == "" && f.ExpiredBefore == nil
}

type ClientStore interface {
	ListClients(ctx context.Context, opts ListOptions) ([]*identity.Client, int, error)
	GetClientById(ctx context.Context, id string) (*identity.Client, error)
	GetClientByClientId(ctx context.Context, clientId string) (*identity.Client, error)
	CreateClient(ctx context.Context, client *identity.Client) error
	UpdateClient(ctx context.Context, client *identity.Client) error
	DeleteClient(ctx context.Context, id string) error
}

type UserStore interface {
	ListUsers(ctx context.Context, filter UserFilter, opts ListOptions) ([]*identity.User, int, error)
	GetUserById(ctx context.Context, id string) (*identity.User, error)
	GetUserByNormalizedUsername(ctx context.Context, normalizedUsername string) (*identity.User, error)
	GetUserByNormalizedEmail(ctx context.Context, normalizedEmail string) (*identity.User, error)
	CreateUser(ctx context.Context, user *identity.User) error
	UpdateUser(ctx context.Context, user *identity.User) error
	DeleteUser(ctx context.Context, id string) error
}

type AccessTokenStore interface {
	ListAccessTokens(ctx context.Context, filter TokenFilter, opts ListOptions) ([]*identity.AccessToken, int, error)
	GetAccessTokenById(ctx context.Context, id string) (*identity.AccessToken, error)
	GetAccessTokenByHash(ctx context.Context, tokenHash string) (*identity.AccessToken, error)
	CreateAccessToken(ctx context.Context, token *identity.AccessToken) error
	DeleteAccessToken(ctx context.Context, id string) error
	// DeleteAccessTokens deletes all tokens matching the filter and returns the number of deleted tokens.
	DeleteAccessTokens(ctx context.Context, filter TokenFilter) (int, error)
}

type RefreshTokenStore interface {
	ListRefreshTokens(ctx context.Context, filter TokenFilter, opts ListOptions) ([]*identity.RefreshToken, int, error)
	GetRefreshTokenById(ctx context.Context, id string) (*identity.RefreshToken, error)
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*identity.RefreshToken, error)
	CreateRefreshToken(ctx context.Context, token *identity.RefreshToken) error
	UpdateRefreshToken(ctx context.Context, token *identity.RefreshToken) error
	DeleteRefreshToken(ctx context.Context, id string) error
	// DeleteRefreshTokens deletes all tokens matching the filter and returns the number of deleted tokens.
	DeleteRefreshTokens(ctx context.Context, filter TokenFilter) (int, error)
}

type AuthorizationCodeStore interface {
	GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*identity.AuthorizationCode, error)
	CreateAuthorizationCode(ctx context.Context, code *identity.AuthorizationCode) error
	// ConsumeAuthorizationCode atomically marks the code as consumed.
	// It returns ErrConflict when the code was already consumed and ErrNotFound when it doesn't exist.
	ConsumeAuthorizationCode(ctx context.Context, id string, consumedAt time.Time) error
	DeleteAuthorizationCode(ctx context.Context, id string) error
	// DeleteExpiredAuthorizationCodes deletes all codes that expire at or before the given time.
	DeleteExpiredAuthorizationCodes(ctx context.Context, before time.Time) (int, error)
}

type UserTokenStore interface {
	GetUserTokenByHash(ctx context.Context, purpose identity.UserTokenPurpose, tokenHash string) (*identity.UserToken, error)
	CreateUserToken(ctx context.Context, token *identity.UserToken) error
	DeleteUserToken(ctx context.Context, id string) error
	// DeleteUserTokens deletes all tokens of the user with the given purpose.
	DeleteUserTokens(ctx context.Context, userId string, purpose identity.UserTokenPurpose) (int, error)
	// DeleteExpiredUserTokens deletes all tokens that expire at or before the given time.
	DeleteExpiredUserTokens(ctx context.Context, before time.Time) (int, error)
}

// Store combines all stores used by the identity server.
type Store interface {
	ClientStore
	UserStore
	AccessTokenStore
	RefreshTokenStore
	AuthorizationCodeStore
	UserTokenStore
}

// DeleteExpired removes all expired tokens and codes.
func DeleteExpired(ctx context.Context, s Store, now time.Time) error {
	filter := TokenFilter{ExpiredBefore: &now}
	if _, err := s.DeleteAccessTokens(ctx, filter); err != nil {
		return err
	}
	if _, err := s.DeleteRefreshTokens(ctx, filter); err != nil {
		return err
	}
	if _, err := s.DeleteExpiredAuthorizationCodes(ctx, now); err != nil {
		return err
	}
	_, err := s.DeleteExpiredUserTokens(ctx, now)
	return err
}
