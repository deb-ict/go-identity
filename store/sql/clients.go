package sqlstore

import (
	"context"
	"strings"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/store"
)

var clientColumns = columnList(tableClients)

func scanClient(row scanner) (*identity.Client, error) {
	var (
		c                                                     identity.Client
		redirectUris, allowedScopes, defaultScopes, grants    string
		accessLifetime, codeLifetime, refreshLifetime         int64
		createdAt, updatedAt                                  int64
		clientType, refreshTokenUsage, refreshTokenExpiration string
	)
	err := row.Scan(
		&c.Id, &c.ClientId, &c.Name, &c.Description, &clientType, &c.SecretHash,
		&redirectUris, &allowedScopes, &defaultScopes, &grants,
		&c.RequireConsent, &c.RequirePkce, &c.Enabled,
		&accessLifetime, &codeLifetime, &refreshTokenUsage, &refreshTokenExpiration, &refreshLifetime,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	c.Type = identity.ClientType(clientType)
	c.RefreshTokenUsage = identity.RefreshTokenUsage(refreshTokenUsage)
	c.RefreshTokenExpiration = identity.RefreshTokenExpirationType(refreshTokenExpiration)
	c.AccessTokenLifetime = time.Duration(accessLifetime)
	c.AuthorizationCodeLifetime = time.Duration(codeLifetime)
	c.RefreshTokenLifetime = time.Duration(refreshLifetime)
	c.CreatedAt = decTime(createdAt)
	c.UpdatedAt = decTime(updatedAt)
	if c.RedirectUris, err = decList[string](redirectUris); err != nil {
		return nil, err
	}
	if c.AllowedScopes, err = decList[string](allowedScopes); err != nil {
		return nil, err
	}
	if c.DefaultScopes, err = decList[string](defaultScopes); err != nil {
		return nil, err
	}
	if c.AllowedGrantTypes, err = decList[identity.GrantType](grants); err != nil {
		return nil, err
	}
	return &c, nil
}

// clientValues returns the column values in the order of clientColumns, without the id.
func clientValues(c *identity.Client) []any {
	return []any{
		c.ClientId, c.Name, c.Description, string(c.Type), c.SecretHash,
		encList(c.RedirectUris), encList(c.AllowedScopes), encList(c.DefaultScopes), encList(c.AllowedGrantTypes),
		c.RequireConsent, c.RequirePkce, c.Enabled,
		int64(c.AccessTokenLifetime), int64(c.AuthorizationCodeLifetime),
		string(c.RefreshTokenUsage), string(c.RefreshTokenExpiration), int64(c.RefreshTokenLifetime),
		encTime(c.CreatedAt), encTime(c.UpdatedAt),
	}
}

func (s *Store) ListClients(ctx context.Context, opts store.ListOptions) ([]*identity.Client, int, error) {
	return list(ctx, s, s.table(tableClients), clientColumns, "", nil, opts, scanClient)
}

func (s *Store) GetClientById(ctx context.Context, id string) (*identity.Client, error) {
	return getOne(s.queryRow(ctx, "SELECT "+clientColumns+" FROM "+s.table(tableClients)+" WHERE id = ?", id), scanClient)
}

func (s *Store) GetClientByClientId(ctx context.Context, clientId string) (*identity.Client, error) {
	return getOne(s.queryRow(ctx, "SELECT "+clientColumns+" FROM "+s.table(tableClients)+" WHERE client_id = ?", clientId), scanClient)
}

func (s *Store) CreateClient(ctx context.Context, client *identity.Client) error {
	args := append([]any{client.Id}, clientValues(client)...)
	_, err := s.exec(ctx, "INSERT INTO "+s.table(tableClients)+" ("+clientColumns+") VALUES ("+placeholders(len(args))+")", args...)
	return mapError(err)
}

func (s *Store) UpdateClient(ctx context.Context, client *identity.Client) error {
	table := s.table(tableClients)
	query := "UPDATE " + table + " SET client_id = ?, name = ?, description = ?, client_type = ?, secret_hash = ?, " +
		"redirect_uris = ?, allowed_scopes = ?, default_scopes = ?, allowed_grant_types = ?, " +
		"require_consent = ?, require_pkce = ?, enabled = ?, " +
		"access_token_lifetime = ?, authorization_code_lifetime = ?, " +
		"refresh_token_usage = ?, refresh_token_expiration = ?, refresh_token_lifetime = ?, " +
		"created_at = ?, updated_at = ? WHERE id = ?"
	args := append(clientValues(client), client.Id)
	return s.execChanged(ctx, table, client.Id, query, args...)
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	return s.execDelete(ctx, s.table(tableClients), id)
}

// placeholders returns n comma separated '?' placeholders.
func placeholders(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteByte('?')
	}
	return b.String()
}
