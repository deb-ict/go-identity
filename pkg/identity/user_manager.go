package identity

import (
	"context"
	"errors"
)

var (
	ErrInvalidCredentials error = errors.New("username or password incorrect")
)

type UserManager interface {
	LoginUser(ctx context.Context, username string, password string) (*User, error)
	GetStore() UserStore
}

func NewUserManager(store UserStore) UserManager {
	return &userManager{
		store:  store,
		hasher: NewSecretHasher(),
	}
}

type userManager struct {
	store  UserStore
	hasher SecretHasher
}

func (manager *userManager) LoginUser(ctx context.Context, username string, password string) (*User, error) {
	user, err := manager.store.GetUserByUserName(ctx, username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	err = manager.hasher.VerifySecret(user.Password, password)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	return user, nil
}

func (manager *userManager) GetStore() UserStore {
	return manager.store
}
