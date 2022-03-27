package mongo

import (
	"context"
	"errors"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type authorizationCodeDocument struct {
	Id              primitive.ObjectID `bson:"_id,omitempty"`
	ClientId        string             `bson:"clientId"`
	Code            string             `bson:"code"`
	RedirectUri     string             `bson:"redirectUri"`
	RequestedScopes []string           `bson:"scopes"`
	CreatedAt       time.Time          `bson:"createdAt"`
	Lifetime        time.Duration      `bons:"lifetime"`
}

type authorizationTokenStore struct {
	db         *database
	collection *mongo.Collection
}

func (store *authorizationTokenStore) GetAuthorizationCode(ctx context.Context, code string) (*identity.AuthorizationCode, error) {
	return nil, errors.New("not implemented")
}

func (store *authorizationTokenStore) CreateAuthorizationCode(ctx context.Context, code *identity.AuthorizationCode) (string, error) {
	return "", errors.New("not implemented")
}

func (store *authorizationTokenStore) DeleteAuthorizationCode(ctx context.Context, code string) error {
	return errors.New("not implemented")
}
