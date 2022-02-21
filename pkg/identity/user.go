package identity

import (
	"context"
	"errors"
)

var (
	ErrUserNotFound   error = errors.New("user not found")
	ErrUserNotCreated error = errors.New("user not created")
	ErrUserNotUpdated error = errors.New("user not updated")
	ErrUserNotDeleted error = errors.New("user not deleted")
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
	Id            string `json:"id"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type UserPage struct {
	PageIndex int     `json:"page_index"`
	PageSize  int     `json:"page_size"`
	Count     int     `json:"count"`
	Items     []*User `json:"items"`
}

type UserSearch struct {
}
