// Package memory provides an in-memory store.Store, suitable for tests and development.
package memory

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/store"
)

var _ store.Store = &Store{}

// Store is a thread-safe in-memory store. All values are copied on the way in and out.
type Store struct {
	mu                 sync.RWMutex
	clients            map[string]*identity.Client
	users              map[string]*identity.User
	accessTokens       map[string]*identity.AccessToken
	refreshTokens      map[string]*identity.RefreshToken
	authorizationCodes map[string]*identity.AuthorizationCode
	userTokens         map[string]*identity.UserToken
}

// New creates an empty in-memory store.
func New() *Store {
	return &Store{
		clients:            map[string]*identity.Client{},
		users:              map[string]*identity.User{},
		accessTokens:       map[string]*identity.AccessToken{},
		refreshTokens:      map[string]*identity.RefreshToken{},
		authorizationCodes: map[string]*identity.AuthorizationCode{},
		userTokens:         map[string]*identity.UserToken{},
	}
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string{}, s...)
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func cloneClient(c *identity.Client) *identity.Client {
	v := *c
	v.RedirectUris = cloneStrings(c.RedirectUris)
	v.AllowedScopes = cloneStrings(c.AllowedScopes)
	v.DefaultScopes = cloneStrings(c.DefaultScopes)
	if c.AllowedGrantTypes != nil {
		v.AllowedGrantTypes = append([]identity.GrantType{}, c.AllowedGrantTypes...)
	}
	return &v
}

func cloneUser(u *identity.User) *identity.User {
	v := *u
	v.LockoutEnd = cloneTime(u.LockoutEnd)
	v.LastLoginAt = cloneTime(u.LastLoginAt)
	return &v
}

func cloneAccessToken(t *identity.AccessToken) *identity.AccessToken {
	v := *t
	v.Scopes = cloneStrings(t.Scopes)
	return &v
}

func cloneRefreshToken(t *identity.RefreshToken) *identity.RefreshToken {
	v := *t
	v.Scopes = cloneStrings(t.Scopes)
	return &v
}

func cloneAuthorizationCode(c *identity.AuthorizationCode) *identity.AuthorizationCode {
	v := *c
	v.Scopes = cloneStrings(c.Scopes)
	v.ConsumedAt = cloneTime(c.ConsumedAt)
	return &v
}

func cloneUserToken(t *identity.UserToken) *identity.UserToken {
	v := *t
	return &v
}

// page sorts the items by creation time and id, and returns the requested page.
func page[T any](items []T, key func(T) (time.Time, string), opts store.ListOptions) ([]T, int) {
	opts = opts.Normalize()
	sort.Slice(items, func(i, j int) bool {
		ti, idi := key(items[i])
		tj, idj := key(items[j])
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return idi < idj
	})
	total := len(items)
	if opts.Offset >= total {
		return []T{}, total
	}
	end := opts.Offset + opts.Limit
	if end > total {
		end = total
	}
	return items[opts.Offset:end], total
}

// Clients

func (s *Store) ListClients(ctx context.Context, opts store.ListOptions) ([]*identity.Client, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]*identity.Client, 0, len(s.clients))
	for _, c := range s.clients {
		items = append(items, c)
	}
	result, total := page(items, func(c *identity.Client) (time.Time, string) { return c.CreatedAt, c.Id }, opts)
	for i := range result {
		result[i] = cloneClient(result[i])
	}
	return result, total, nil
}

func (s *Store) GetClientById(ctx context.Context, id string) (*identity.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneClient(c), nil
}

func (s *Store) GetClientByClientId(ctx context.Context, clientId string) (*identity.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.clients {
		if c.ClientId == clientId {
			return cloneClient(c), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) clientIdTaken(clientId string, exceptId string) bool {
	for _, c := range s.clients {
		if c.ClientId == clientId && c.Id != exceptId {
			return true
		}
	}
	return false
}

func (s *Store) CreateClient(ctx context.Context, client *identity.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[client.Id]; ok || s.clientIdTaken(client.ClientId, "") {
		return store.ErrDuplicate
	}
	s.clients[client.Id] = cloneClient(client)
	return nil
}

func (s *Store) UpdateClient(ctx context.Context, client *identity.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[client.Id]; !ok {
		return store.ErrNotFound
	}
	if s.clientIdTaken(client.ClientId, client.Id) {
		return store.ErrDuplicate
	}
	s.clients[client.Id] = cloneClient(client)
	return nil
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.clients, id)
	return nil
}

// Users

func (s *Store) ListUsers(ctx context.Context, filter store.UserFilter, opts store.ListOptions) ([]*identity.User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	search := strings.ToLower(filter.Search)
	items := make([]*identity.User, 0, len(s.users))
	for _, u := range s.users {
		if search != "" && !strings.Contains(u.NormalizedUsername, search) && !strings.Contains(u.NormalizedEmail, search) {
			continue
		}
		items = append(items, u)
	}
	result, total := page(items, func(u *identity.User) (time.Time, string) { return u.CreatedAt, u.Id }, opts)
	for i := range result {
		result[i] = cloneUser(result[i])
	}
	return result, total, nil
}

func (s *Store) GetUserById(ctx context.Context, id string) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

func (s *Store) GetUserByNormalizedUsername(ctx context.Context, normalizedUsername string) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.NormalizedUsername == normalizedUsername {
			return cloneUser(u), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) GetUserByNormalizedEmail(ctx context.Context, normalizedEmail string) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.NormalizedEmail == normalizedEmail {
			return cloneUser(u), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) userTaken(user *identity.User, exceptId string) bool {
	for _, u := range s.users {
		if u.Id != exceptId && (u.NormalizedUsername == user.NormalizedUsername || u.NormalizedEmail == user.NormalizedEmail) {
			return true
		}
	}
	return false
}

func (s *Store) CreateUser(ctx context.Context, user *identity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user.Id]; ok || s.userTaken(user, "") {
		return store.ErrDuplicate
	}
	s.users[user.Id] = cloneUser(user)
	return nil
}

func (s *Store) UpdateUser(ctx context.Context, user *identity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user.Id]; !ok {
		return store.ErrNotFound
	}
	if s.userTaken(user, user.Id) {
		return store.ErrDuplicate
	}
	s.users[user.Id] = cloneUser(user)
	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.users, id)
	return nil
}

// Tokens

type tokenFields struct {
	clientId, userId, codeId string
	expiresAt                time.Time
}

func matchToken(f store.TokenFilter, t tokenFields) bool {
	if f.ClientId != "" && f.ClientId != t.clientId {
		return false
	}
	if f.UserId != "" && f.UserId != t.userId {
		return false
	}
	if f.AuthorizationCodeId != "" && f.AuthorizationCodeId != t.codeId {
		return false
	}
	if f.ExpiredBefore != nil && t.expiresAt.After(*f.ExpiredBefore) {
		return false
	}
	return true
}

func accessTokenFields(t *identity.AccessToken) tokenFields {
	return tokenFields{t.ClientId, t.UserId, t.AuthorizationCodeId, t.ExpiresAt}
}

func refreshTokenFields(t *identity.RefreshToken) tokenFields {
	return tokenFields{t.ClientId, t.UserId, t.AuthorizationCodeId, t.ExpiresAt}
}

func (s *Store) ListAccessTokens(ctx context.Context, filter store.TokenFilter, opts store.ListOptions) ([]*identity.AccessToken, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := []*identity.AccessToken{}
	for _, t := range s.accessTokens {
		if matchToken(filter, accessTokenFields(t)) {
			items = append(items, t)
		}
	}
	result, total := page(items, func(t *identity.AccessToken) (time.Time, string) { return t.CreatedAt, t.Id }, opts)
	for i := range result {
		result[i] = cloneAccessToken(result[i])
	}
	return result, total, nil
}

func (s *Store) GetAccessTokenById(ctx context.Context, id string) (*identity.AccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.accessTokens[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneAccessToken(t), nil
}

func (s *Store) GetAccessTokenByHash(ctx context.Context, tokenHash string) (*identity.AccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.accessTokens {
		if t.TokenHash == tokenHash {
			return cloneAccessToken(t), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) CreateAccessToken(ctx context.Context, token *identity.AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accessTokens[token.Id]; ok {
		return store.ErrDuplicate
	}
	for _, t := range s.accessTokens {
		if t.TokenHash == token.TokenHash {
			return store.ErrDuplicate
		}
	}
	s.accessTokens[token.Id] = cloneAccessToken(token)
	return nil
}

func (s *Store) DeleteAccessToken(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accessTokens[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.accessTokens, id)
	return nil
}

func (s *Store) DeleteAccessTokens(ctx context.Context, filter store.TokenFilter) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, t := range s.accessTokens {
		if matchToken(filter, accessTokenFields(t)) {
			delete(s.accessTokens, id)
			n++
		}
	}
	return n, nil
}

func (s *Store) ListRefreshTokens(ctx context.Context, filter store.TokenFilter, opts store.ListOptions) ([]*identity.RefreshToken, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := []*identity.RefreshToken{}
	for _, t := range s.refreshTokens {
		if matchToken(filter, refreshTokenFields(t)) {
			items = append(items, t)
		}
	}
	result, total := page(items, func(t *identity.RefreshToken) (time.Time, string) { return t.CreatedAt, t.Id }, opts)
	for i := range result {
		result[i] = cloneRefreshToken(result[i])
	}
	return result, total, nil
}

func (s *Store) GetRefreshTokenById(ctx context.Context, id string) (*identity.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.refreshTokens[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneRefreshToken(t), nil
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*identity.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.refreshTokens {
		if t.TokenHash == tokenHash {
			return cloneRefreshToken(t), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) CreateRefreshToken(ctx context.Context, token *identity.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.refreshTokens[token.Id]; ok {
		return store.ErrDuplicate
	}
	for _, t := range s.refreshTokens {
		if t.TokenHash == token.TokenHash {
			return store.ErrDuplicate
		}
	}
	s.refreshTokens[token.Id] = cloneRefreshToken(token)
	return nil
}

func (s *Store) UpdateRefreshToken(ctx context.Context, token *identity.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.refreshTokens[token.Id]; !ok {
		return store.ErrNotFound
	}
	for _, t := range s.refreshTokens {
		if t.TokenHash == token.TokenHash && t.Id != token.Id {
			return store.ErrDuplicate
		}
	}
	s.refreshTokens[token.Id] = cloneRefreshToken(token)
	return nil
}

func (s *Store) DeleteRefreshToken(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.refreshTokens[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.refreshTokens, id)
	return nil
}

func (s *Store) DeleteRefreshTokens(ctx context.Context, filter store.TokenFilter) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, t := range s.refreshTokens {
		if matchToken(filter, refreshTokenFields(t)) {
			delete(s.refreshTokens, id)
			n++
		}
	}
	return n, nil
}

// Authorization codes

func (s *Store) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*identity.AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.authorizationCodes {
		if c.CodeHash == codeHash {
			return cloneAuthorizationCode(c), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) CreateAuthorizationCode(ctx context.Context, code *identity.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.authorizationCodes[code.Id]; ok {
		return store.ErrDuplicate
	}
	for _, c := range s.authorizationCodes {
		if c.CodeHash == code.CodeHash {
			return store.ErrDuplicate
		}
	}
	s.authorizationCodes[code.Id] = cloneAuthorizationCode(code)
	return nil
}

func (s *Store) ConsumeAuthorizationCode(ctx context.Context, id string, consumedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.authorizationCodes[id]
	if !ok {
		return store.ErrNotFound
	}
	if c.ConsumedAt != nil {
		return store.ErrConflict
	}
	c.ConsumedAt = &consumedAt
	return nil
}

func (s *Store) DeleteAuthorizationCode(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.authorizationCodes[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.authorizationCodes, id)
	return nil
}

func (s *Store) DeleteExpiredAuthorizationCodes(ctx context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, c := range s.authorizationCodes {
		if !c.ExpiresAt.After(before) {
			delete(s.authorizationCodes, id)
			n++
		}
	}
	return n, nil
}

// User tokens

func (s *Store) GetUserTokenByHash(ctx context.Context, purpose identity.UserTokenPurpose, tokenHash string) (*identity.UserToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.userTokens {
		if t.Purpose == purpose && t.TokenHash == tokenHash {
			return cloneUserToken(t), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) CreateUserToken(ctx context.Context, token *identity.UserToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.userTokens[token.Id]; ok {
		return store.ErrDuplicate
	}
	for _, t := range s.userTokens {
		if t.TokenHash == token.TokenHash {
			return store.ErrDuplicate
		}
	}
	s.userTokens[token.Id] = cloneUserToken(token)
	return nil
}

func (s *Store) DeleteUserToken(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.userTokens[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.userTokens, id)
	return nil
}

func (s *Store) DeleteUserTokens(ctx context.Context, userId string, purpose identity.UserTokenPurpose) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, t := range s.userTokens {
		if t.UserId == userId && t.Purpose == purpose {
			delete(s.userTokens, id)
			n++
		}
	}
	return n, nil
}

func (s *Store) DeleteExpiredUserTokens(ctx context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, t := range s.userTokens {
		if !t.ExpiresAt.After(before) {
			delete(s.userTokens, id)
			n++
		}
	}
	return n, nil
}
