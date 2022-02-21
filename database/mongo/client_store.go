package mongo

import (
	"context"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type clientDocument struct {
	Id                     primitive.ObjectID `bson:"_id,omitempty"`
	ClientId               string             `bson:"clientId"`
	ClientSecret           string             `bson:"clientSecret"`
	RedirectUris           []string           `bson:"redirectUris"`
	AllowedScopes          []string           `bson:"allowedScopes"`
	RefreshTokenUsage      string             `bson:"refreshTokenUsage"`
	RefreshTokenExpiration string             `bson:"refreshTokenExpiration"`
	RefreshTokenLifetime   time.Duration      `bson:"refreshTokenLifetime"`
	IsDeleted              bool               `bson:"isDeleted"`
}

type clientStore struct {
	db         *database
	collection *mongo.Collection
}

func (doc *clientDocument) toViewModel() *identity.Client {
	return &identity.Client{
		Id:                     doc.Id.Hex(),
		ClientId:               doc.ClientId,
		ClientSecret:           doc.ClientSecret,
		RedirectUris:           doc.RedirectUris,
		AllowedScopes:          doc.AllowedScopes,
		RefreshTokenUsage:      identity.RefreshTokenUsage(doc.RefreshTokenUsage),
		RefreshTokenExpiration: identity.RefreshTokenExpirationType(doc.RefreshTokenExpiration),
		RefreshTokenLifetime:   doc.RefreshTokenLifetime,
	}
}

func (store *clientStore) GetClients(ctx context.Context, search identity.ClientSearch, pageIndex int, pageSize int) (*identity.ClientPage, error) {
	pageIndex, pageSize = store.db.getNormalizedPaging(pageIndex, pageSize)

	filter := bson.M{}
	findOptions := options.Find()

	// Get the total number of items
	totalItems, err := store.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, err
	}

	findOptions.SetSkip((int64(pageIndex) - 1) * int64(pageSize))
	findOptions.SetLimit(int64(pageSize))
	cursor, err := store.collection.Find(ctx, filter, findOptions)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var data []*identity.Client
	for cursor.Next(ctx) {
		var doc clientDocument
		cursor.Decode(&doc)
		data = append(data, doc.toViewModel())
	}

	return &identity.ClientPage{
		PageIndex: pageIndex,
		PageSize:  pageSize,
		Count:     int(totalItems),
		Items:     data,
	}, nil
}

func (store *clientStore) GetClientById(ctx context.Context, id string) (*identity.Client, error) {
	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": objectId, "isDeleted": false}
	result := store.collection.FindOne(ctx, filter)
	if err := result.Err(); err != nil {
		return nil, err
	}

	var doc clientDocument
	err = result.Decode(&doc)
	if err != nil {
		return nil, err
	}

	return doc.toViewModel(), nil
}

func (store *clientStore) GetClientByClientId(ctx context.Context, clientId string) (*identity.Client, error) {
	filter := bson.M{"clientId": clientId, "isDeleted": false}
	result := store.collection.FindOne(ctx, filter)
	if err := result.Err(); err != nil {
		return nil, err
	}

	var doc clientDocument
	err := result.Decode(&doc)
	if err != nil {
		return nil, err
	}

	return doc.toViewModel(), nil
}

func (store *clientStore) CreateClient(ctx context.Context, client *identity.Client) (string, error) {
	doc := clientDocument{
		ClientId:               client.ClientId,
		ClientSecret:           client.ClientSecret,
		RedirectUris:           client.RedirectUris,
		AllowedScopes:          client.AllowedScopes,
		RefreshTokenUsage:      string(client.RefreshTokenUsage),
		RefreshTokenExpiration: string(client.RefreshTokenExpiration),
		RefreshTokenLifetime:   client.RefreshTokenLifetime,
		IsDeleted:              false,
	}

	result, err := store.collection.InsertOne(ctx, doc)
	if err != nil {
		return "", err
	}

	newid, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		return "", identity.ErrClientNotCreated
	}

	return newid.Hex(), nil
}

func (store *clientStore) UpdateClient(ctx context.Context, id string, client *identity.Client) error {
	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": objectId}
	update := bson.M{
		"clientSecret":           client.ClientSecret,
		"redirectUris":           client.RedirectUris,
		"allowedScopes":          client.AllowedScopes,
		"refreshTokenUsage":      string(client.RefreshTokenUsage),
		"refreshTokenExpiration": string(client.RefreshTokenExpiration),
		"refreshTokenLifetime":   client.RefreshTokenLifetime,
	}

	result, err := store.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return identity.ErrClientNotUpdated
	}
	return nil
}

func (store *clientStore) DeleteClient(ctx context.Context, id string) error {
	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": objectId}
	update := bson.M{"isDeleted": true}

	result, err := store.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return identity.ErrClientNotDeleted
	}
	return nil
}
