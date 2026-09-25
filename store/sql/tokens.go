package sqlstore

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/store"
)

var (
	accessTokenColumns       = columnList(tableAccessTokens)
	refreshTokenColumns      = columnList(tableRefreshTokens)
	authorizationCodeColumns = columnList(tableAuthorizationCodes)
	userTokenColumns         = columnList(tableUserTokens)
)

// tokenWhere builds the WHERE clause (with leading space) of a token filter. Empty fields are ignored.
func tokenWhere(filter store.TokenFilter) (string, []any) {
	conditions := []string{}
	args := []any{}
	if filter.ClientId != "" {
		conditions = append(conditions, "client_id = ?")
		args = append(args, filter.ClientId)
	}
	if filter.UserId != "" {
		conditions = append(conditions, "user_id = ?")
		args = append(args, filter.UserId)
	}
	if filter.AuthorizationCodeId != "" {
		conditions = append(conditions, "authorization_code_id = ?")
		args = append(args, filter.AuthorizationCodeId)
	}
	if filter.ExpiredBefore != nil {
		conditions = append(conditions, "expires_at <= ?")
		args = append(args, encTime(*filter.ExpiredBefore))
	}
	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

// Access tokens

func scanAccessToken(row scanner) (*identity.AccessToken, error) {
	var (
		t                    identity.AccessToken
		scopes               string
		createdAt, expiresAt int64
	)
	err := row.Scan(&t.Id, &t.TokenHash, &t.ClientId, &t.UserId, &scopes, &t.AuthorizationCodeId, &createdAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	t.CreatedAt = decTime(createdAt)
	t.ExpiresAt = decTime(expiresAt)
	if t.Scopes, err = decList[string](scopes); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListAccessTokens(ctx context.Context, filter store.TokenFilter, opts store.ListOptions) ([]*identity.AccessToken, int, error) {
	where, args := tokenWhere(filter)
	return list(ctx, s, s.table(tableAccessTokens), accessTokenColumns, where, args, opts, scanAccessToken)
}

func (s *Store) GetAccessTokenById(ctx context.Context, id string) (*identity.AccessToken, error) {
	return getOne(s.queryRow(ctx, "SELECT "+accessTokenColumns+" FROM "+s.table(tableAccessTokens)+" WHERE id = ?", id), scanAccessToken)
}

func (s *Store) GetAccessTokenByHash(ctx context.Context, tokenHash string) (*identity.AccessToken, error) {
	return getOne(s.queryRow(ctx, "SELECT "+accessTokenColumns+" FROM "+s.table(tableAccessTokens)+" WHERE token_hash = ?", tokenHash), scanAccessToken)
}

func (s *Store) CreateAccessToken(ctx context.Context, token *identity.AccessToken) error {
	args := []any{
		token.Id, token.TokenHash, token.ClientId, token.UserId, encList(token.Scopes), token.AuthorizationCodeId,
		encTime(token.CreatedAt), encTime(token.ExpiresAt),
	}
	_, err := s.exec(ctx, "INSERT INTO "+s.table(tableAccessTokens)+" ("+accessTokenColumns+") VALUES ("+placeholders(len(args))+")", args...)
	return mapError(err)
}

func (s *Store) DeleteAccessToken(ctx context.Context, id string) error {
	return s.execDelete(ctx, s.table(tableAccessTokens), id)
}

func (s *Store) DeleteAccessTokens(ctx context.Context, filter store.TokenFilter) (int, error) {
	where, args := tokenWhere(filter)
	return s.execCount(ctx, "DELETE FROM "+s.table(tableAccessTokens)+where, args...)
}

// Refresh tokens

func scanRefreshToken(row scanner) (*identity.RefreshToken, error) {
	var (
		t                               identity.RefreshToken
		scopes, expiration, usage       string
		lifetime                        int64
		createdAt, updatedAt, expiresAt int64
	)
	err := row.Scan(
		&t.Id, &t.TokenHash, &t.ClientId, &t.UserId, &t.AccessTokenId, &t.AuthorizationCodeId, &scopes,
		&expiration, &usage, &lifetime, &createdAt, &updatedAt, &expiresAt,
	)
	if err != nil {
		return nil, err
	}
	t.TokenExpiration = identity.RefreshTokenExpirationType(expiration)
	t.TokenUsage = identity.RefreshTokenUsage(usage)
	t.Lifetime = time.Duration(lifetime)
	t.CreatedAt = decTime(createdAt)
	t.UpdatedAt = decTime(updatedAt)
	t.ExpiresAt = decTime(expiresAt)
	if t.Scopes, err = decList[string](scopes); err != nil {
		return nil, err
	}
	return &t, nil
}

// refreshTokenValues returns the column values in the order of refreshTokenColumns, without the id.
func refreshTokenValues(t *identity.RefreshToken) []any {
	return []any{
		t.TokenHash, t.ClientId, t.UserId, t.AccessTokenId, t.AuthorizationCodeId, encList(t.Scopes),
		string(t.TokenExpiration), string(t.TokenUsage), int64(t.Lifetime),
		encTime(t.CreatedAt), encTime(t.UpdatedAt), encTime(t.ExpiresAt),
	}
}

func (s *Store) ListRefreshTokens(ctx context.Context, filter store.TokenFilter, opts store.ListOptions) ([]*identity.RefreshToken, int, error) {
	where, args := tokenWhere(filter)
	return list(ctx, s, s.table(tableRefreshTokens), refreshTokenColumns, where, args, opts, scanRefreshToken)
}

func (s *Store) GetRefreshTokenById(ctx context.Context, id string) (*identity.RefreshToken, error) {
	return getOne(s.queryRow(ctx, "SELECT "+refreshTokenColumns+" FROM "+s.table(tableRefreshTokens)+" WHERE id = ?", id), scanRefreshToken)
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*identity.RefreshToken, error) {
	return getOne(s.queryRow(ctx, "SELECT "+refreshTokenColumns+" FROM "+s.table(tableRefreshTokens)+" WHERE token_hash = ?", tokenHash), scanRefreshToken)
}

func (s *Store) CreateRefreshToken(ctx context.Context, token *identity.RefreshToken) error {
	args := append([]any{token.Id}, refreshTokenValues(token)...)
	_, err := s.exec(ctx, "INSERT INTO "+s.table(tableRefreshTokens)+" ("+refreshTokenColumns+") VALUES ("+placeholders(len(args))+")", args...)
	return mapError(err)
}

func (s *Store) UpdateRefreshToken(ctx context.Context, token *identity.RefreshToken) error {
	table := s.table(tableRefreshTokens)
	query := "UPDATE " + table + " SET token_hash = ?, client_id = ?, user_id = ?, access_token_id = ?, authorization_code_id = ?, scopes = ?, " +
		"token_expiration = ?, token_usage = ?, lifetime = ?, created_at = ?, updated_at = ?, expires_at = ? WHERE id = ?"
	args := append(refreshTokenValues(token), token.Id)
	return s.execChanged(ctx, table, token.Id, query, args...)
}

func (s *Store) DeleteRefreshToken(ctx context.Context, id string) error {
	return s.execDelete(ctx, s.table(tableRefreshTokens), id)
}

func (s *Store) DeleteRefreshTokens(ctx context.Context, filter store.TokenFilter) (int, error) {
	where, args := tokenWhere(filter)
	return s.execCount(ctx, "DELETE FROM "+s.table(tableRefreshTokens)+where, args...)
}

// Authorization codes

func scanAuthorizationCode(row scanner) (*identity.AuthorizationCode, error) {
	var (
		c                    identity.AuthorizationCode
		scopes               string
		createdAt, expiresAt int64
		consumedAt           sql.NullInt64
	)
	err := row.Scan(
		&c.Id, &c.CodeHash, &c.ClientId, &c.UserId, &scopes, &c.RedirectUri, &c.CodeChallenge, &c.CodeChallengeMethod,
		&createdAt, &expiresAt, &consumedAt,
	)
	if err != nil {
		return nil, err
	}
	c.CreatedAt = decTime(createdAt)
	c.ExpiresAt = decTime(expiresAt)
	c.ConsumedAt = decTimePtr(consumedAt)
	if c.Scopes, err = decList[string](scopes); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*identity.AuthorizationCode, error) {
	return getOne(s.queryRow(ctx, "SELECT "+authorizationCodeColumns+" FROM "+s.table(tableAuthorizationCodes)+" WHERE code_hash = ?", codeHash), scanAuthorizationCode)
}

func (s *Store) CreateAuthorizationCode(ctx context.Context, code *identity.AuthorizationCode) error {
	args := []any{
		code.Id, code.CodeHash, code.ClientId, code.UserId, encList(code.Scopes), code.RedirectUri, code.CodeChallenge, code.CodeChallengeMethod,
		encTime(code.CreatedAt), encTime(code.ExpiresAt), encTimePtr(code.ConsumedAt),
	}
	_, err := s.exec(ctx, "INSERT INTO "+s.table(tableAuthorizationCodes)+" ("+authorizationCodeColumns+") VALUES ("+placeholders(len(args))+")", args...)
	return mapError(err)
}

func (s *Store) ConsumeAuthorizationCode(ctx context.Context, id string, consumedAt time.Time) error {
	table := s.table(tableAuthorizationCodes)
	n, err := s.execCount(ctx, "UPDATE "+table+" SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL", encTime(consumedAt), id)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	exists, err := s.exists(ctx, table, id)
	if err != nil {
		return err
	}
	if !exists {
		return store.ErrNotFound
	}
	return store.ErrConflict
}

func (s *Store) DeleteAuthorizationCode(ctx context.Context, id string) error {
	return s.execDelete(ctx, s.table(tableAuthorizationCodes), id)
}

func (s *Store) DeleteExpiredAuthorizationCodes(ctx context.Context, before time.Time) (int, error) {
	return s.execCount(ctx, "DELETE FROM "+s.table(tableAuthorizationCodes)+" WHERE expires_at <= ?", encTime(before))
}

// User tokens

func scanUserToken(row scanner) (*identity.UserToken, error) {
	var (
		t                    identity.UserToken
		purpose              string
		createdAt, expiresAt int64
	)
	if err := row.Scan(&t.Id, &t.UserId, &purpose, &t.TokenHash, &createdAt, &expiresAt); err != nil {
		return nil, err
	}
	t.Purpose = identity.UserTokenPurpose(purpose)
	t.CreatedAt = decTime(createdAt)
	t.ExpiresAt = decTime(expiresAt)
	return &t, nil
}

func (s *Store) GetUserTokenByHash(ctx context.Context, purpose identity.UserTokenPurpose, tokenHash string) (*identity.UserToken, error) {
	return getOne(s.queryRow(ctx, "SELECT "+userTokenColumns+" FROM "+s.table(tableUserTokens)+" WHERE token_hash = ? AND purpose = ?", tokenHash, string(purpose)), scanUserToken)
}

func (s *Store) CreateUserToken(ctx context.Context, token *identity.UserToken) error {
	args := []any{token.Id, token.UserId, string(token.Purpose), token.TokenHash, encTime(token.CreatedAt), encTime(token.ExpiresAt)}
	_, err := s.exec(ctx, "INSERT INTO "+s.table(tableUserTokens)+" ("+userTokenColumns+") VALUES ("+placeholders(len(args))+")", args...)
	return mapError(err)
}

func (s *Store) DeleteUserToken(ctx context.Context, id string) error {
	return s.execDelete(ctx, s.table(tableUserTokens), id)
}

func (s *Store) DeleteUserTokens(ctx context.Context, userId string, purpose identity.UserTokenPurpose) (int, error) {
	return s.execCount(ctx, "DELETE FROM "+s.table(tableUserTokens)+" WHERE user_id = ? AND purpose = ?", userId, string(purpose))
}

func (s *Store) DeleteExpiredUserTokens(ctx context.Context, before time.Time) (int, error) {
	return s.execCount(ctx, "DELETE FROM "+s.table(tableUserTokens)+" WHERE expires_at <= ?", encTime(before))
}
