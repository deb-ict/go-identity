// Package storetest contains a conformance test suite for store.Store implementations.
//
//	func TestStore(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) store.Store {
//			return newEmptyStore(t)
//		})
//	}
package storetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/store"
)

// Factory returns a new, empty store.
type Factory func(t *testing.T) store.Store

// Run executes the conformance suite against stores created by the factory.
func Run(t *testing.T, factory Factory) {
	t.Run("Clients", func(t *testing.T) { testClients(t, factory(t)) })
	t.Run("ClientList", func(t *testing.T) { testClientList(t, factory(t)) })
	t.Run("Users", func(t *testing.T) { testUsers(t, factory(t)) })
	t.Run("UserList", func(t *testing.T) { testUserList(t, factory(t)) })
	t.Run("AccessTokens", func(t *testing.T) { testAccessTokens(t, factory(t)) })
	t.Run("RefreshTokens", func(t *testing.T) { testRefreshTokens(t, factory(t)) })
	t.Run("AuthorizationCodes", func(t *testing.T) { testAuthorizationCodes(t, factory(t)) })
	t.Run("UserTokens", func(t *testing.T) { testUserTokens(t, factory(t)) })
	t.Run("DeleteExpired", func(t *testing.T) { testDeleteExpired(t, factory(t)) })
}

// base is millisecond precision, the lowest precision a store is allowed to use.
var base = time.Date(2024, 1, 2, 3, 4, 5, 6_000_000, time.UTC)

func at(minutes int) time.Time {
	return base.Add(time.Duration(minutes) * time.Minute)
}

func ptr(t time.Time) *time.Time {
	return &t
}

func expectErr(t *testing.T, err error, target error, what string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: expected %v, got %v", what, target, err)
	}
}

func expectNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", what, err)
	}
}

func equalTime(a time.Time, b time.Time) bool {
	return a.Equal(b)
}

func equalTimePtr(a *time.Time, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func equalStrings(a []string, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func equalGrantTypes(a []identity.GrantType, b []identity.GrantType) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func newClient(id string, clientId string, created time.Time) *identity.Client {
	return &identity.Client{
		Id:                        id,
		ClientId:                  clientId,
		Name:                      "Client " + clientId,
		Description:               "Description of " + clientId,
		Type:                      identity.ClientTypeConfidential,
		SecretHash:                "hash-" + clientId,
		RedirectUris:              []string{"https://example.com/cb", "https://example.com/cb2"},
		AllowedScopes:             []string{"api.read", "api.write"},
		DefaultScopes:             []string{"api.read"},
		AllowedGrantTypes:         []identity.GrantType{identity.GrantTypeAuthorizationCode, identity.GrantTypeRefreshToken},
		RequireConsent:            true,
		RequirePkce:               true,
		Enabled:                   true,
		AccessTokenLifetime:       10 * time.Minute,
		AuthorizationCodeLifetime: 2 * time.Minute,
		RefreshTokenUsage:         identity.RefreshTokenUsageOneTime,
		RefreshTokenExpiration:    identity.RefreshTokenExpirationAbsolute,
		RefreshTokenLifetime:      48 * time.Hour,
		CreatedAt:                 created,
		UpdatedAt:                 created,
	}
}

func compareClient(t *testing.T, expected *identity.Client, actual *identity.Client) {
	t.Helper()
	if actual == nil {
		t.Fatalf("client %s: got nil", expected.Id)
	}
	e, a := *expected, *actual
	if !equalStrings(e.RedirectUris, a.RedirectUris) || !equalStrings(e.AllowedScopes, a.AllowedScopes) ||
		!equalStrings(e.DefaultScopes, a.DefaultScopes) || !equalGrantTypes(e.AllowedGrantTypes, a.AllowedGrantTypes) ||
		!equalTime(e.CreatedAt, a.CreatedAt) || !equalTime(e.UpdatedAt, a.UpdatedAt) {
		t.Fatalf("client mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
	e.RedirectUris, a.RedirectUris = nil, nil
	e.AllowedScopes, a.AllowedScopes = nil, nil
	e.DefaultScopes, a.DefaultScopes = nil, nil
	e.AllowedGrantTypes, a.AllowedGrantTypes = nil, nil
	e.CreatedAt, a.CreatedAt = time.Time{}, time.Time{}
	e.UpdatedAt, a.UpdatedAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(e, a) {
		t.Fatalf("client mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
}

func testClients(t *testing.T, s store.Store) {
	ctx := context.Background()

	_, err := s.GetClientById(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing client")
	_, err = s.GetClientByClientId(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing client by client id")

	client := newClient("c1", "client-one", at(0))
	expectNoErr(t, s.CreateClient(ctx, client), "create client")

	// The store must not keep a reference to the caller's value
	client.Name = "changed after create"
	client.RedirectUris[0] = "https://changed"
	expected := newClient("c1", "client-one", at(0))

	got, err := s.GetClientById(ctx, "c1")
	expectNoErr(t, err, "get client")
	compareClient(t, expected, got)

	got, err = s.GetClientByClientId(ctx, "client-one")
	expectNoErr(t, err, "get client by client id")
	compareClient(t, expected, got)

	// Duplicates
	expectErr(t, s.CreateClient(ctx, newClient("c1", "other", at(0))), store.ErrDuplicate, "create duplicate id")
	expectErr(t, s.CreateClient(ctx, newClient("c2", "client-one", at(0))), store.ErrDuplicate, "create duplicate client id")

	// Update
	expectNoErr(t, s.CreateClient(ctx, newClient("c2", "client-two", at(1))), "create second client")
	updated := newClient("c1", "client-one-renamed", at(0))
	updated.Name = "Renamed"
	updated.Type = identity.ClientTypePublic
	updated.SecretHash = ""
	updated.RedirectUris = []string{}
	updated.AllowedScopes = []string{"x"}
	updated.DefaultScopes = nil
	updated.AllowedGrantTypes = []identity.GrantType{identity.GrantTypeImplicit}
	updated.RequireConsent = false
	updated.RequirePkce = false
	updated.Enabled = false
	updated.RefreshTokenUsage = identity.RefreshTokenUsageReUse
	updated.RefreshTokenExpiration = identity.RefreshTokenExpirationSliding
	updated.UpdatedAt = at(5)
	expectNoErr(t, s.UpdateClient(ctx, updated), "update client")
	got, err = s.GetClientById(ctx, "c1")
	expectNoErr(t, err, "get updated client")
	compareClient(t, updated, got)
	_, err = s.GetClientByClientId(ctx, "client-one")
	expectErr(t, err, store.ErrNotFound, "old client id after rename")

	dup := newClient("c1", "client-two", at(0))
	expectErr(t, s.UpdateClient(ctx, dup), store.ErrDuplicate, "update to duplicate client id")
	expectErr(t, s.UpdateClient(ctx, newClient("missing", "missing", at(0))), store.ErrNotFound, "update missing client")

	// Delete
	expectNoErr(t, s.DeleteClient(ctx, "c1"), "delete client")
	_, err = s.GetClientById(ctx, "c1")
	expectErr(t, err, store.ErrNotFound, "get deleted client")
	expectErr(t, s.DeleteClient(ctx, "c1"), store.ErrNotFound, "delete missing client")
}

func testClientList(t *testing.T, s store.Store) {
	ctx := context.Background()

	items, total, err := s.ListClients(ctx, store.ListOptions{})
	expectNoErr(t, err, "list empty")
	if total != 0 || len(items) != 0 {
		t.Fatalf("expected empty list, got %d/%d", len(items), total)
	}

	// Insert out of order, ordering is by creation time, then id
	expectNoErr(t, s.CreateClient(ctx, newClient("c3", "client-3", at(3))), "create")
	expectNoErr(t, s.CreateClient(ctx, newClient("c1", "client-1", at(1))), "create")
	expectNoErr(t, s.CreateClient(ctx, newClient("c2b", "client-2b", at(2))), "create")
	expectNoErr(t, s.CreateClient(ctx, newClient("c2a", "client-2a", at(2))), "create")

	items, total, err = s.ListClients(ctx, store.ListOptions{Offset: 0, Limit: 10})
	expectNoErr(t, err, "list")
	if total != 4 {
		t.Fatalf("expected total 4, got %d", total)
	}
	ids := []string{}
	for _, item := range items {
		ids = append(ids, item.Id)
	}
	if !reflect.DeepEqual(ids, []string{"c1", "c2a", "c2b", "c3"}) {
		t.Fatalf("unexpected order: %v", ids)
	}

	items, total, err = s.ListClients(ctx, store.ListOptions{Offset: 1, Limit: 2})
	expectNoErr(t, err, "list page")
	if total != 4 || len(items) != 2 || items[0].Id != "c2a" || items[1].Id != "c2b" {
		t.Fatalf("unexpected page: total=%d len=%d", total, len(items))
	}
	compareClient(t, newClient("c2a", "client-2a", at(2)), items[0])

	items, total, err = s.ListClients(ctx, store.ListOptions{Offset: 10, Limit: 2})
	expectNoErr(t, err, "list beyond end")
	if total != 4 || len(items) != 0 {
		t.Fatalf("unexpected page beyond end: total=%d len=%d", total, len(items))
	}
}

func newUser(id string, username string, created time.Time) *identity.User {
	user := &identity.User{
		Id:               id,
		Username:         username,
		Email:            username + "@Example.com",
		PasswordHash:     "hash-" + username,
		EmailVerified:    true,
		Enabled:          true,
		SecurityStamp:    "stamp-" + username,
		FailedLoginCount: 2,
		LockoutEnd:       ptr(created.Add(time.Hour)),
		LastLoginAt:      ptr(created.Add(time.Minute)),
		CreatedAt:        created,
		UpdatedAt:        created,
	}
	user.Normalize()
	return user
}

func compareUser(t *testing.T, expected *identity.User, actual *identity.User) {
	t.Helper()
	if actual == nil {
		t.Fatalf("user %s: got nil", expected.Id)
	}
	e, a := *expected, *actual
	if !equalTimePtr(e.LockoutEnd, a.LockoutEnd) || !equalTimePtr(e.LastLoginAt, a.LastLoginAt) ||
		!equalTime(e.CreatedAt, a.CreatedAt) || !equalTime(e.UpdatedAt, a.UpdatedAt) {
		t.Fatalf("user mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
	e.LockoutEnd, a.LockoutEnd = nil, nil
	e.LastLoginAt, a.LastLoginAt = nil, nil
	e.CreatedAt, a.CreatedAt = time.Time{}, time.Time{}
	e.UpdatedAt, a.UpdatedAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(e, a) {
		t.Fatalf("user mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
}

func testUsers(t *testing.T, s store.Store) {
	ctx := context.Background()

	_, err := s.GetUserById(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing user")
	_, err = s.GetUserByNormalizedUsername(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing user by username")
	_, err = s.GetUserByNormalizedEmail(ctx, "missing@example.com")
	expectErr(t, err, store.ErrNotFound, "get missing user by email")

	user := newUser("u1", "Alice", at(0))
	expectNoErr(t, s.CreateUser(ctx, user), "create user")
	user.Email = "changed after create"
	expected := newUser("u1", "Alice", at(0))

	got, err := s.GetUserById(ctx, "u1")
	expectNoErr(t, err, "get user")
	compareUser(t, expected, got)
	got, err = s.GetUserByNormalizedUsername(ctx, "alice")
	expectNoErr(t, err, "get user by username")
	compareUser(t, expected, got)
	got, err = s.GetUserByNormalizedEmail(ctx, "alice@example.com")
	expectNoErr(t, err, "get user by email")
	compareUser(t, expected, got)

	// Duplicates
	expectErr(t, s.CreateUser(ctx, newUser("u1", "other", at(0))), store.ErrDuplicate, "create duplicate id")
	dupUsername := newUser("u2", "ALICE", at(0))
	dupUsername.Email = "unique@example.com"
	dupUsername.Normalize()
	expectErr(t, s.CreateUser(ctx, dupUsername), store.ErrDuplicate, "create duplicate username")
	dupEmail := newUser("u2", "bob", at(0))
	dupEmail.Email = "alice@example.com"
	dupEmail.Normalize()
	expectErr(t, s.CreateUser(ctx, dupEmail), store.ErrDuplicate, "create duplicate email")

	// Nil optional fields
	bob := newUser("u2", "bob", at(1))
	bob.LockoutEnd = nil
	bob.LastLoginAt = nil
	expectNoErr(t, s.CreateUser(ctx, bob), "create bob")
	got, err = s.GetUserById(ctx, "u2")
	expectNoErr(t, err, "get bob")
	compareUser(t, bob, got)

	// Update
	updated := newUser("u1", "alice2", at(0))
	updated.EmailVerified = false
	updated.Enabled = false
	updated.FailedLoginCount = 0
	updated.LockoutEnd = nil
	updated.LastLoginAt = ptr(at(9))
	updated.UpdatedAt = at(10)
	expectNoErr(t, s.UpdateUser(ctx, updated), "update user")
	got, err = s.GetUserById(ctx, "u1")
	expectNoErr(t, err, "get updated user")
	compareUser(t, updated, got)
	_, err = s.GetUserByNormalizedUsername(ctx, "alice")
	expectErr(t, err, store.ErrNotFound, "old username after rename")

	conflict := newUser("u1", "bob", at(0))
	conflict.Email = "alice-unique@example.com"
	conflict.Normalize()
	expectErr(t, s.UpdateUser(ctx, conflict), store.ErrDuplicate, "update to duplicate username")
	expectErr(t, s.UpdateUser(ctx, newUser("missing", "missing", at(0))), store.ErrNotFound, "update missing user")

	// Delete
	expectNoErr(t, s.DeleteUser(ctx, "u1"), "delete user")
	_, err = s.GetUserById(ctx, "u1")
	expectErr(t, err, store.ErrNotFound, "get deleted user")
	expectErr(t, s.DeleteUser(ctx, "u1"), store.ErrNotFound, "delete missing user")
}

func testUserList(t *testing.T, s store.Store) {
	ctx := context.Background()

	expectNoErr(t, s.CreateUser(ctx, newUser("u3", "charlie", at(3))), "create")
	expectNoErr(t, s.CreateUser(ctx, newUser("u1", "alice", at(1))), "create")
	expectNoErr(t, s.CreateUser(ctx, newUser("u2", "bob", at(2))), "create")
	other := newUser("u4", "dave", at(4))
	other.Email = "dave@other.org"
	other.Normalize()
	expectNoErr(t, s.CreateUser(ctx, other), "create")

	items, total, err := s.ListUsers(ctx, store.UserFilter{}, store.ListOptions{Limit: 10})
	expectNoErr(t, err, "list users")
	if total != 4 || len(items) != 4 || items[0].Id != "u1" || items[3].Id != "u4" {
		t.Fatalf("unexpected list: total=%d len=%d", total, len(items))
	}

	items, total, err = s.ListUsers(ctx, store.UserFilter{}, store.ListOptions{Offset: 1, Limit: 1})
	expectNoErr(t, err, "list users page")
	if total != 4 || len(items) != 1 || items[0].Id != "u2" {
		t.Fatalf("unexpected page: total=%d len=%d", total, len(items))
	}

	items, total, err = s.ListUsers(ctx, store.UserFilter{Search: "EXAMPLE"}, store.ListOptions{Limit: 10})
	expectNoErr(t, err, "search by email")
	if total != 3 || len(items) != 3 {
		t.Fatalf("expected 3 users matching 'EXAMPLE', got %d/%d", len(items), total)
	}

	items, total, err = s.ListUsers(ctx, store.UserFilter{Search: "Ob"}, store.ListOptions{Limit: 10})
	expectNoErr(t, err, "search by username")
	if total != 1 || len(items) != 1 || items[0].Id != "u2" {
		t.Fatalf("expected bob for 'Ob', got %d/%d", len(items), total)
	}

	items, total, err = s.ListUsers(ctx, store.UserFilter{Search: "%"}, store.ListOptions{Limit: 10})
	expectNoErr(t, err, "search wildcard")
	if total != 0 || len(items) != 0 {
		t.Fatalf("search must be literal, got %d/%d for '%%'", len(items), total)
	}
}

func newAccessToken(id string, clientId string, userId string, codeId string, created time.Time, expires time.Time) *identity.AccessToken {
	return &identity.AccessToken{
		Id:                  id,
		TokenHash:           "hash-" + id,
		ClientId:            clientId,
		UserId:              userId,
		Scopes:              []string{"api.read", "api.write"},
		AuthorizationCodeId: codeId,
		CreatedAt:           created,
		ExpiresAt:           expires,
	}
}

func compareAccessToken(t *testing.T, expected *identity.AccessToken, actual *identity.AccessToken) {
	t.Helper()
	if actual == nil {
		t.Fatalf("access token %s: got nil", expected.Id)
	}
	e, a := *expected, *actual
	if !equalStrings(e.Scopes, a.Scopes) || !equalTime(e.CreatedAt, a.CreatedAt) || !equalTime(e.ExpiresAt, a.ExpiresAt) {
		t.Fatalf("access token mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
	e.Scopes, a.Scopes = nil, nil
	e.CreatedAt, a.CreatedAt = time.Time{}, time.Time{}
	e.ExpiresAt, a.ExpiresAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(e, a) {
		t.Fatalf("access token mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
}

func ids[T any](items []T, id func(T) string) []string {
	result := []string{}
	for _, item := range items {
		result = append(result, id(item))
	}
	return result
}

func testAccessTokens(t *testing.T, s store.Store) {
	ctx := context.Background()

	_, err := s.GetAccessTokenById(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing access token")
	_, err = s.GetAccessTokenByHash(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing access token by hash")

	token := newAccessToken("a1", "client1", "user1", "code1", at(0), at(60))
	expectNoErr(t, s.CreateAccessToken(ctx, token), "create access token")
	token.Scopes[0] = "changed"
	expected := newAccessToken("a1", "client1", "user1", "code1", at(0), at(60))

	got, err := s.GetAccessTokenById(ctx, "a1")
	expectNoErr(t, err, "get access token")
	compareAccessToken(t, expected, got)
	got, err = s.GetAccessTokenByHash(ctx, "hash-a1")
	expectNoErr(t, err, "get access token by hash")
	compareAccessToken(t, expected, got)

	expectErr(t, s.CreateAccessToken(ctx, newAccessToken("a1", "c", "u", "", at(0), at(1))), store.ErrDuplicate, "duplicate id")
	dup := newAccessToken("a9", "c", "u", "", at(0), at(1))
	dup.TokenHash = "hash-a1"
	expectErr(t, s.CreateAccessToken(ctx, dup), store.ErrDuplicate, "duplicate hash")

	// Client credentials tokens have no user
	noUser := newAccessToken("a2", "client1", "", "", at(1), at(30))
	noUser.Scopes = []string{}
	expectNoErr(t, s.CreateAccessToken(ctx, noUser), "create token without user")
	expectNoErr(t, s.CreateAccessToken(ctx, newAccessToken("a3", "client2", "user1", "", at(2), at(90))), "create")
	expectNoErr(t, s.CreateAccessToken(ctx, newAccessToken("a4", "client2", "user2", "code2", at(3), at(120))), "create")

	got, err = s.GetAccessTokenById(ctx, "a2")
	expectNoErr(t, err, "get token without user")
	compareAccessToken(t, noUser, got)

	cases := []struct {
		filter   store.TokenFilter
		expected []string
	}{
		{store.TokenFilter{}, []string{"a1", "a2", "a3", "a4"}},
		{store.TokenFilter{ClientId: "client1"}, []string{"a1", "a2"}},
		{store.TokenFilter{UserId: "user1"}, []string{"a1", "a3"}},
		{store.TokenFilter{ClientId: "client2", UserId: "user1"}, []string{"a3"}},
		{store.TokenFilter{AuthorizationCodeId: "code2"}, []string{"a4"}},
		{store.TokenFilter{ExpiredBefore: ptr(at(60))}, []string{"a1", "a2"}},
		{store.TokenFilter{ClientId: "nobody"}, []string{}},
	}
	for i, c := range cases {
		items, total, err := s.ListAccessTokens(ctx, c.filter, store.ListOptions{Limit: 10})
		expectNoErr(t, err, "list access tokens")
		got := ids(items, func(t *identity.AccessToken) string { return t.Id })
		if total != len(c.expected) || !reflect.DeepEqual(got, c.expected) {
			t.Fatalf("case %d: expected %v, got %v (total %d)", i, c.expected, got, total)
		}
	}
	items, total, err := s.ListAccessTokens(ctx, store.TokenFilter{}, store.ListOptions{Offset: 2, Limit: 1})
	expectNoErr(t, err, "list page")
	if total != 4 || len(items) != 1 || items[0].Id != "a3" {
		t.Fatalf("unexpected page")
	}

	// Delete
	expectNoErr(t, s.DeleteAccessToken(ctx, "a1"), "delete access token")
	_, err = s.GetAccessTokenById(ctx, "a1")
	expectErr(t, err, store.ErrNotFound, "get deleted access token")
	expectErr(t, s.DeleteAccessToken(ctx, "a1"), store.ErrNotFound, "delete missing access token")

	n, err := s.DeleteAccessTokens(ctx, store.TokenFilter{ClientId: "client2", UserId: "user2"})
	expectNoErr(t, err, "delete by filter")
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}
	n, err = s.DeleteAccessTokens(ctx, store.TokenFilter{ClientId: "nobody"})
	expectNoErr(t, err, "delete by filter without match")
	if n != 0 {
		t.Fatalf("expected 0 deleted, got %d", n)
	}
	n, err = s.DeleteAccessTokens(ctx, store.TokenFilter{})
	expectNoErr(t, err, "delete all")
	if n != 2 {
		t.Fatalf("expected 2 deleted, got %d", n)
	}
}

func newRefreshToken(id string, clientId string, userId string, created time.Time, expires time.Time) *identity.RefreshToken {
	return &identity.RefreshToken{
		Id:                  id,
		TokenHash:           "hash-" + id,
		ClientId:            clientId,
		UserId:              userId,
		AccessTokenId:       "access-" + id,
		AuthorizationCodeId: "code-" + id,
		Scopes:              []string{"api.read", "offline"},
		TokenExpiration:     identity.RefreshTokenExpirationSliding,
		TokenUsage:          identity.RefreshTokenUsageOneTime,
		Lifetime:            24 * time.Hour,
		CreatedAt:           created,
		UpdatedAt:           created,
		ExpiresAt:           expires,
	}
}

func compareRefreshToken(t *testing.T, expected *identity.RefreshToken, actual *identity.RefreshToken) {
	t.Helper()
	if actual == nil {
		t.Fatalf("refresh token %s: got nil", expected.Id)
	}
	e, a := *expected, *actual
	if !equalStrings(e.Scopes, a.Scopes) || !equalTime(e.CreatedAt, a.CreatedAt) ||
		!equalTime(e.UpdatedAt, a.UpdatedAt) || !equalTime(e.ExpiresAt, a.ExpiresAt) {
		t.Fatalf("refresh token mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
	e.Scopes, a.Scopes = nil, nil
	e.CreatedAt, a.CreatedAt = time.Time{}, time.Time{}
	e.UpdatedAt, a.UpdatedAt = time.Time{}, time.Time{}
	e.ExpiresAt, a.ExpiresAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(e, a) {
		t.Fatalf("refresh token mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
}

func testRefreshTokens(t *testing.T, s store.Store) {
	ctx := context.Background()

	_, err := s.GetRefreshTokenById(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing refresh token")
	_, err = s.GetRefreshTokenByHash(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing refresh token by hash")

	token := newRefreshToken("r1", "client1", "user1", at(0), at(100))
	expectNoErr(t, s.CreateRefreshToken(ctx, token), "create refresh token")
	token.Scopes[0] = "changed"
	expected := newRefreshToken("r1", "client1", "user1", at(0), at(100))

	got, err := s.GetRefreshTokenById(ctx, "r1")
	expectNoErr(t, err, "get refresh token")
	compareRefreshToken(t, expected, got)
	got, err = s.GetRefreshTokenByHash(ctx, "hash-r1")
	expectNoErr(t, err, "get refresh token by hash")
	compareRefreshToken(t, expected, got)

	expectErr(t, s.CreateRefreshToken(ctx, newRefreshToken("r1", "c", "u", at(0), at(1))), store.ErrDuplicate, "duplicate id")
	dup := newRefreshToken("r9", "c", "u", at(0), at(1))
	dup.TokenHash = "hash-r1"
	expectErr(t, s.CreateRefreshToken(ctx, dup), store.ErrDuplicate, "duplicate hash")

	// Update
	expected.AccessTokenId = "access-new"
	expected.UpdatedAt = at(10)
	expected.ExpiresAt = at(200)
	expectNoErr(t, s.UpdateRefreshToken(ctx, expected), "update refresh token")
	got, err = s.GetRefreshTokenById(ctx, "r1")
	expectNoErr(t, err, "get updated refresh token")
	compareRefreshToken(t, expected, got)
	expectErr(t, s.UpdateRefreshToken(ctx, newRefreshToken("missing", "c", "u", at(0), at(1))), store.ErrNotFound, "update missing refresh token")

	// List & filter
	expectNoErr(t, s.CreateRefreshToken(ctx, newRefreshToken("r2", "client1", "user2", at(1), at(50))), "create")
	expectNoErr(t, s.CreateRefreshToken(ctx, newRefreshToken("r3", "client2", "user1", at(2), at(300))), "create")
	cases := []struct {
		filter   store.TokenFilter
		expected []string
	}{
		{store.TokenFilter{}, []string{"r1", "r2", "r3"}},
		{store.TokenFilter{ClientId: "client1"}, []string{"r1", "r2"}},
		{store.TokenFilter{UserId: "user1"}, []string{"r1", "r3"}},
		{store.TokenFilter{AuthorizationCodeId: "code-r2"}, []string{"r2"}},
		{store.TokenFilter{ExpiredBefore: ptr(at(200))}, []string{"r1", "r2"}},
	}
	for i, c := range cases {
		items, total, err := s.ListRefreshTokens(ctx, c.filter, store.ListOptions{Limit: 10})
		expectNoErr(t, err, "list refresh tokens")
		got := ids(items, func(t *identity.RefreshToken) string { return t.Id })
		if total != len(c.expected) || !reflect.DeepEqual(got, c.expected) {
			t.Fatalf("case %d: expected %v, got %v (total %d)", i, c.expected, got, total)
		}
	}

	// Delete
	expectNoErr(t, s.DeleteRefreshToken(ctx, "r1"), "delete refresh token")
	expectErr(t, s.DeleteRefreshToken(ctx, "r1"), store.ErrNotFound, "delete missing refresh token")
	n, err := s.DeleteRefreshTokens(ctx, store.TokenFilter{UserId: "user1"})
	expectNoErr(t, err, "delete by filter")
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}
	_, total, err := s.ListRefreshTokens(ctx, store.TokenFilter{}, store.ListOptions{})
	expectNoErr(t, err, "list remaining")
	if total != 1 {
		t.Fatalf("expected 1 remaining, got %d", total)
	}
}

func newAuthorizationCode(id string, created time.Time, expires time.Time) *identity.AuthorizationCode {
	return &identity.AuthorizationCode{
		Id:                  id,
		CodeHash:            "hash-" + id,
		ClientId:            "client1",
		UserId:              "user1",
		Scopes:              []string{"api.read"},
		RedirectUri:         "https://example.com/cb",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		CreatedAt:           created,
		ExpiresAt:           expires,
	}
}

func compareAuthorizationCode(t *testing.T, expected *identity.AuthorizationCode, actual *identity.AuthorizationCode) {
	t.Helper()
	if actual == nil {
		t.Fatalf("authorization code %s: got nil", expected.Id)
	}
	e, a := *expected, *actual
	if !equalStrings(e.Scopes, a.Scopes) || !equalTime(e.CreatedAt, a.CreatedAt) ||
		!equalTime(e.ExpiresAt, a.ExpiresAt) || !equalTimePtr(e.ConsumedAt, a.ConsumedAt) {
		t.Fatalf("authorization code mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
	e.Scopes, a.Scopes = nil, nil
	e.CreatedAt, a.CreatedAt = time.Time{}, time.Time{}
	e.ExpiresAt, a.ExpiresAt = time.Time{}, time.Time{}
	e.ConsumedAt, a.ConsumedAt = nil, nil
	if !reflect.DeepEqual(e, a) {
		t.Fatalf("authorization code mismatch:\nexpected %+v\nactual   %+v", e, a)
	}
}

func testAuthorizationCodes(t *testing.T, s store.Store) {
	ctx := context.Background()

	_, err := s.GetAuthorizationCodeByHash(ctx, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing code")

	code := newAuthorizationCode("ac1", at(0), at(5))
	expectNoErr(t, s.CreateAuthorizationCode(ctx, code), "create code")
	expectErr(t, s.CreateAuthorizationCode(ctx, newAuthorizationCode("ac1", at(0), at(5))), store.ErrDuplicate, "duplicate id")
	dup := newAuthorizationCode("ac9", at(0), at(5))
	dup.CodeHash = "hash-ac1"
	expectErr(t, s.CreateAuthorizationCode(ctx, dup), store.ErrDuplicate, "duplicate hash")

	got, err := s.GetAuthorizationCodeByHash(ctx, "hash-ac1")
	expectNoErr(t, err, "get code")
	compareAuthorizationCode(t, newAuthorizationCode("ac1", at(0), at(5)), got)

	// Consume exactly once
	expectNoErr(t, s.ConsumeAuthorizationCode(ctx, "ac1", at(1)), "consume code")
	expectErr(t, s.ConsumeAuthorizationCode(ctx, "ac1", at(2)), store.ErrConflict, "consume code twice")
	expectErr(t, s.ConsumeAuthorizationCode(ctx, "missing", at(2)), store.ErrNotFound, "consume missing code")
	got, err = s.GetAuthorizationCodeByHash(ctx, "hash-ac1")
	expectNoErr(t, err, "get consumed code")
	expected := newAuthorizationCode("ac1", at(0), at(5))
	expected.ConsumedAt = ptr(at(1))
	compareAuthorizationCode(t, expected, got)

	// Expired cleanup
	expectNoErr(t, s.CreateAuthorizationCode(ctx, newAuthorizationCode("ac2", at(0), at(10))), "create code 2")
	expectNoErr(t, s.CreateAuthorizationCode(ctx, newAuthorizationCode("ac3", at(0), at(20))), "create code 3")
	n, err := s.DeleteExpiredAuthorizationCodes(ctx, at(10))
	expectNoErr(t, err, "delete expired codes")
	if n != 2 {
		t.Fatalf("expected 2 expired codes deleted, got %d", n)
	}
	_, err = s.GetAuthorizationCodeByHash(ctx, "hash-ac2")
	expectErr(t, err, store.ErrNotFound, "expired code deleted")

	expectNoErr(t, s.DeleteAuthorizationCode(ctx, "ac3"), "delete code")
	expectErr(t, s.DeleteAuthorizationCode(ctx, "ac3"), store.ErrNotFound, "delete missing code")
}

func testUserTokens(t *testing.T, s store.Store) {
	ctx := context.Background()

	activation := identity.UserTokenPurposeActivation
	reset := identity.UserTokenPurposePasswordReset
	newToken := func(id string, userId string, purpose identity.UserTokenPurpose, expires time.Time) *identity.UserToken {
		return &identity.UserToken{Id: id, UserId: userId, Purpose: purpose, TokenHash: "hash-" + id, CreatedAt: at(0), ExpiresAt: expires}
	}

	_, err := s.GetUserTokenByHash(ctx, activation, "missing")
	expectErr(t, err, store.ErrNotFound, "get missing user token")

	expectNoErr(t, s.CreateUserToken(ctx, newToken("t1", "u1", activation, at(10))), "create")
	expectNoErr(t, s.CreateUserToken(ctx, newToken("t2", "u1", reset, at(20))), "create")
	expectNoErr(t, s.CreateUserToken(ctx, newToken("t3", "u1", reset, at(30))), "create")
	expectNoErr(t, s.CreateUserToken(ctx, newToken("t4", "u2", reset, at(40))), "create")
	expectErr(t, s.CreateUserToken(ctx, newToken("t1", "u1", activation, at(10))), store.ErrDuplicate, "duplicate")

	got, err := s.GetUserTokenByHash(ctx, activation, "hash-t1")
	expectNoErr(t, err, "get user token")
	expected := newToken("t1", "u1", activation, at(10))
	if got.Id != expected.Id || got.UserId != expected.UserId || got.Purpose != expected.Purpose ||
		got.TokenHash != expected.TokenHash || !got.CreatedAt.Equal(expected.CreatedAt) || !got.ExpiresAt.Equal(expected.ExpiresAt) {
		t.Fatalf("user token mismatch:\nexpected %+v\nactual   %+v", expected, got)
	}
	_, err = s.GetUserTokenByHash(ctx, reset, "hash-t1")
	expectErr(t, err, store.ErrNotFound, "get user token with wrong purpose")

	n, err := s.DeleteUserTokens(ctx, "u1", reset)
	expectNoErr(t, err, "delete user tokens")
	if n != 2 {
		t.Fatalf("expected 2 deleted, got %d", n)
	}
	_, err = s.GetUserTokenByHash(ctx, activation, "hash-t1")
	expectNoErr(t, err, "activation token must survive")

	n, err = s.DeleteExpiredUserTokens(ctx, at(10))
	expectNoErr(t, err, "delete expired user tokens")
	if n != 1 {
		t.Fatalf("expected 1 expired deleted, got %d", n)
	}

	expectNoErr(t, s.DeleteUserToken(ctx, "t4"), "delete user token")
	expectErr(t, s.DeleteUserToken(ctx, "t4"), store.ErrNotFound, "delete missing user token")
}

func testDeleteExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		id := fmt.Sprint(i)
		expires := at(i * 10)
		expectNoErr(t, s.CreateAccessToken(ctx, newAccessToken("a"+id, "c", "u", "", at(0), expires)), "create")
		expectNoErr(t, s.CreateRefreshToken(ctx, newRefreshToken("r"+id, "c", "u", at(0), expires)), "create")
		expectNoErr(t, s.CreateAuthorizationCode(ctx, newAuthorizationCode("ac"+id, at(0), expires)), "create")
		expectNoErr(t, s.CreateUserToken(ctx, &identity.UserToken{
			Id: "t" + id, UserId: "u", Purpose: identity.UserTokenPurposeActivation,
			TokenHash: "hash-t" + id, CreatedAt: at(0), ExpiresAt: expires,
		}), "create")
	}
	expectNoErr(t, store.DeleteExpired(ctx, s, at(15)), "delete expired")

	_, total, err := s.ListAccessTokens(ctx, store.TokenFilter{}, store.ListOptions{})
	expectNoErr(t, err, "list")
	if total != 2 {
		t.Fatalf("expected 2 access tokens remaining, got %d", total)
	}
	_, total, err = s.ListRefreshTokens(ctx, store.TokenFilter{}, store.ListOptions{})
	expectNoErr(t, err, "list")
	if total != 2 {
		t.Fatalf("expected 2 refresh tokens remaining, got %d", total)
	}
	_, err = s.GetAuthorizationCodeByHash(ctx, "hash-ac1")
	expectErr(t, err, store.ErrNotFound, "expired code")
	_, err = s.GetAuthorizationCodeByHash(ctx, "hash-ac2")
	expectNoErr(t, err, "valid code")
	_, err = s.GetUserTokenByHash(ctx, identity.UserTokenPurposeActivation, "hash-t1")
	expectErr(t, err, store.ErrNotFound, "expired user token")
	_, err = s.GetUserTokenByHash(ctx, identity.UserTokenPurposeActivation, "hash-t2")
	expectNoErr(t, err, "valid user token")
}
