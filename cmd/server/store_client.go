package main

import "errors"

type ClientStore interface {
	GetClientById(id string) (*Client, error)
}

type Client struct {
	ClientId     string
	ClientSecret string
	RedirectUri  string
}

func (c *Client) ValidateSecret(secret string) error {
	if c.ClientSecret != secret {
		return errors.New("")
	}
	return nil
}

type clientStore struct {
	clients map[string]*Client
}

func NewClientStore() ClientStore {
	store := clientStore{
		clients: make(map[string]*Client),
	}

	store.clients["myclient"] = &Client{
		ClientId:     "myclient",
		ClientSecret: "mysecret",
	}

	return &store
}

func (store *clientStore) GetClientById(id string) (*Client, error) {
	client := store.clients[id]
	if client == nil {
		return nil, errors.New("client not found")
	}
	return client, nil
}
