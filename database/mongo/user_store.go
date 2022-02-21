package mongo

import (
	"context"

	"github.com/deb-ict/go-identity/pkg/identity"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type userDocument struct {
	Id            primitive.ObjectID `bson:"_id,omitempty"`
	UserName      string             `bson:"username"`
	Password      string             `bson:"password"`
	Email         string             `bson:"email"`
	EmailVerified bool               `bson:"emailVerified"`
	IsDeleted     bool               `bson:"isDeleted"`
}

type userStore struct {
	db         *database
	collection *mongo.Collection
}

func (doc *userDocument) toViewModel() *identity.User {
	return &identity.User{
		Id:            doc.Id.Hex(),
		Username:      doc.UserName,
		Password:      doc.Password,
		Email:         doc.Email,
		EmailVerified: doc.EmailVerified,
	}
}

func (store *userStore) GetUsers(ctx context.Context, search identity.UserSearch, pageIndex int, pageSize int) (*identity.UserPage, error) {
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

	var data []*identity.User
	for cursor.Next(ctx) {
		var doc userDocument
		cursor.Decode(&doc)
		data = append(data, doc.toViewModel())
	}

	return &identity.UserPage{
		PageIndex: pageIndex,
		PageSize:  pageSize,
		Count:     int(totalItems),
		Items:     data,
	}, nil
}

func (store *userStore) GetUserById(ctx context.Context, id string) (*identity.User, error) {
	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": objectId, "isDeleted": false}
	result := store.collection.FindOne(ctx, filter)
	if err := result.Err(); err != nil {
		return nil, err
	}

	var doc userDocument
	err = result.Decode(&doc)
	if err != nil {
		return nil, err
	}

	return doc.toViewModel(), nil
}

func (store *userStore) GetUserByUserName(ctx context.Context, userName string) (*identity.User, error) {
	filter := bson.M{"username": userName, "isDeleted": false}
	result := store.collection.FindOne(ctx, filter)
	if err := result.Err(); err != nil {
		return nil, err
	}

	var doc userDocument
	err := result.Decode(&doc)
	if err != nil {
		return nil, err
	}

	return doc.toViewModel(), nil
}

func (store *userStore) CreateUser(ctx context.Context, user *identity.User) (string, error) {
	doc := userDocument{
		UserName:      user.Username,
		Password:      user.Password,
		Email:         user.Email,
		EmailVerified: false,
		IsDeleted:     false,
	}

	result, err := store.collection.InsertOne(ctx, doc)
	if err != nil {
		return "", err
	}

	newid, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		return "", identity.ErrUserNotCreated
	}

	return newid.Hex(), nil
}

func (store *userStore) UpdateUser(ctx context.Context, id string, user *identity.User) error {
	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": objectId}
	update := bson.M{
		"password":      user.Password,
		"email":         user.Email,
		"emailVerified": user.EmailVerified,
	}

	result, err := store.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return identity.ErrUserNotUpdated
	}
	return nil
}

func (store *userStore) DeleteUser(ctx context.Context, id string) error {
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
		return identity.ErrUserNotDeleted
	}
	return nil
}
