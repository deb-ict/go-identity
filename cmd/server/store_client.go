package main

import (
	"errors"

	"github.com/deb-ict/go-identity/pkg/identity"
)

type clientStore struct {
	clients map[string]*identity.Client
}

func NewClientStore() identity.ClientStore {
	store := clientStore{
		clients: make(map[string]*identity.Client),
	}

	s, _ := ClientSecretHasher.HashSecret("mysecret")
	store.clients["myclient"] = &identity.Client{
		ClientId:     "myclient",
		ClientSecret: s,
	}

	return &store
}

func (store *clientStore) GetClientById(id string) (*identity.Client, error) {
	client := store.clients[id]
	if client == nil {
		return nil, errors.New("client not found")
	}
	return client, nil
}
