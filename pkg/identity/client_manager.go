package identity

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/response"
)

type ClientManager interface {
	GetClientFromRequest(w http.ResponseWriter, r *http.Request) (*Client, error)
	GetStore() ClientStore
	SetStore(store ClientStore)
	GetSecretHasher() SecretHasher
	SetSecretHasher(hasher SecretHasher)
}

func NewClientManager(store ClientStore) ClientManager {
	return &clientManager{
		store:  store,
		hasher: NewSecretHasher(),
	}
}

type clientManager struct {
	store  ClientStore
	hasher SecretHasher
}

func (manager *clientManager) GetClientFromRequest(w http.ResponseWriter, r *http.Request) (*Client, error) {
	clientId, clientSecret, useBasicAuth := r.BasicAuth()
	if !useBasicAuth {
		clientId = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client, err := manager.store.GetClientByClientId(r.Context(), clientId)
	if err != nil {
		if useBasicAuth {
			response.InvalidClientAuth(w)
		} else {
			response.InvalidClient(w)
		}
		return nil, err
	}

	err = manager.hasher.VerifySecret(client.ClientSecret, clientSecret)
	if err != nil {
		if useBasicAuth {
			response.InvalidClientAuth(w)
		} else {
			response.InvalidClient(w)
		}
		return nil, err
	}

	return client, nil
}

func (manager *clientManager) GetStore() ClientStore {
	return manager.store
}

func (manager *clientManager) SetStore(store ClientStore) {
	manager.store = store
}

func (manager *clientManager) GetSecretHasher() SecretHasher {
	return manager.hasher
}

func (manager *clientManager) SetSecretHasher(hasher SecretHasher) {
	manager.hasher = hasher
}
