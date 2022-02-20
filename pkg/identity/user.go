package identity

import (
	"context"
	"errors"
)

var (
	ErrUserNotCreated error = errors.New("failed to create user")
	ErrUserNotUpdated error = errors.New("failed to update user")
	ErrUserNotDeleted error = errors.New("failed to delete user")
)

type UserStore interface {
	GetUsers(ctx context.Context, search UserSearch, pageIndex int, pageSize int) (*UserPage, error)
	GetUserById(ctx context.Context, id string) (*User, error)
	GetUserByUserName(ctx context.Context, userName string) (*User, error)
	CreateUser(ctx context.Context, user *User) (string, error)
	UpdateUser(ctx context.Context, id string, user *User) error
	DeleteUser(ctx context.Context, id string) error
}

type User struct {
	Username      string
	Password      string
	Email         string
	EmailVerified bool
}

type UserPage struct {
	PageIndex int
	PageSize  int
	Count     int
	Items     []*User
}

type UserSearch struct {
}
