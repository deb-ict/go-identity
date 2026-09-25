package sqlstore

import (
	"context"
	"database/sql"
	"strings"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/store"
)

var userColumns = columnList(tableUsers)

func scanUser(row scanner) (*identity.User, error) {
	var (
		u                       identity.User
		failedLoginCount        int64
		lockoutEnd, lastLoginAt sql.NullInt64
		createdAt, updatedAt    int64
	)
	err := row.Scan(
		&u.Id, &u.Username, &u.NormalizedUsername, &u.Email, &u.NormalizedEmail, &u.PasswordHash,
		&u.EmailVerified, &u.Enabled, &u.SecurityStamp, &failedLoginCount,
		&lockoutEnd, &lastLoginAt, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.FailedLoginCount = int(failedLoginCount)
	u.LockoutEnd = decTimePtr(lockoutEnd)
	u.LastLoginAt = decTimePtr(lastLoginAt)
	u.CreatedAt = decTime(createdAt)
	u.UpdatedAt = decTime(updatedAt)
	return &u, nil
}

// userValues returns the column values in the order of userColumns, without the id.
func userValues(u *identity.User) []any {
	return []any{
		u.Username, u.NormalizedUsername, u.Email, u.NormalizedEmail, u.PasswordHash,
		u.EmailVerified, u.Enabled, u.SecurityStamp, int64(u.FailedLoginCount),
		encTimePtr(u.LockoutEnd), encTimePtr(u.LastLoginAt), encTime(u.CreatedAt), encTime(u.UpdatedAt),
	}
}

func (s *Store) ListUsers(ctx context.Context, filter store.UserFilter, opts store.ListOptions) ([]*identity.User, int, error) {
	where := ""
	var args []any
	if filter.Search != "" {
		pattern := "%" + escapeLike(strings.ToLower(filter.Search)) + "%"
		where = " WHERE (normalized_username LIKE ? ESCAPE '" + likeEscape + "' OR normalized_email LIKE ? ESCAPE '" + likeEscape + "')"
		args = []any{pattern, pattern}
	}
	return list(ctx, s, s.table(tableUsers), userColumns, where, args, opts, scanUser)
}

func (s *Store) getUser(ctx context.Context, column string, value string) (*identity.User, error) {
	return getOne(s.queryRow(ctx, "SELECT "+userColumns+" FROM "+s.table(tableUsers)+" WHERE "+column+" = ?", value), scanUser)
}

func (s *Store) GetUserById(ctx context.Context, id string) (*identity.User, error) {
	return s.getUser(ctx, "id", id)
}

func (s *Store) GetUserByNormalizedUsername(ctx context.Context, normalizedUsername string) (*identity.User, error) {
	return s.getUser(ctx, "normalized_username", normalizedUsername)
}

func (s *Store) GetUserByNormalizedEmail(ctx context.Context, normalizedEmail string) (*identity.User, error) {
	return s.getUser(ctx, "normalized_email", normalizedEmail)
}

func (s *Store) CreateUser(ctx context.Context, user *identity.User) error {
	args := append([]any{user.Id}, userValues(user)...)
	_, err := s.exec(ctx, "INSERT INTO "+s.table(tableUsers)+" ("+userColumns+") VALUES ("+placeholders(len(args))+")", args...)
	return mapError(err)
}

func (s *Store) UpdateUser(ctx context.Context, user *identity.User) error {
	table := s.table(tableUsers)
	query := "UPDATE " + table + " SET username = ?, normalized_username = ?, email = ?, normalized_email = ?, password_hash = ?, " +
		"email_verified = ?, enabled = ?, security_stamp = ?, failed_login_count = ?, " +
		"lockout_end = ?, last_login_at = ?, created_at = ?, updated_at = ? WHERE id = ?"
	args := append(userValues(user), user.Id)
	return s.execChanged(ctx, table, user.Id, query, args...)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.execDelete(ctx, s.table(tableUsers), id)
}
