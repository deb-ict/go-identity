package main

import (
	"errors"

	"github.com/deb-ict/go-identity/pkg/identity"
)

type userStore struct {
	users []*identity.User
}

func NewUserStore() identity.UserStore {
	store := userStore{}

	return &store
}

func (store *userStore) GetUserByUserName(userName string) (*identity.User, error) {
	for _, user := range store.users {
		if user.Username == userName {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}
