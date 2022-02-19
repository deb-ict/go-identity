package mongo

import (
	"context"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type Database interface {
	Open() error
	Close() error
	GetConfig() Config
	GetClientStore() identity.ClientStore
}

func NewDatabase() Database {
	return &database{
		config: NewConfig(),
	}
}

type database struct {
	config   Config
	client   *mongo.Client
	database *mongo.Database
}

func (db *database) Open() error {
	var err error
	client, err := mongo.NewClient(options.Client().ApplyURI(db.config.GetUri()))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		return err
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return err
	}

	db.client = client
	db.database = client.Database(db.config.GetDatabase())

	return nil
}

func (db *database) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := db.client.Disconnect(ctx)
	if err != nil {
		return err
	}

	db.database = nil
	db.client = nil

	return nil
}

func (db *database) GetConfig() Config {
	return db.config
}

func (db *database) GetClientStore() identity.ClientStore {
	collection := db.database.Collection("client")
	return &clientStore{
		db:         db,
		collection: collection,
	}
}

func (db *database) getNormalizedPaging(pageIndex int, pageSize int) (int, int) {
	return db.getNormalizedPageIndex(pageIndex), db.getNormalizedPageSize(pageSize)
}

func (db *database) getNormalizedPageIndex(pageIndex int) int {
	if pageIndex < 1 {
		return 1
	}
	return pageIndex
}

func (db *database) getNormalizedPageSize(pageSize int) int {
	if pageSize > identity.MaxPageSize {
		return identity.MaxPageSize
	}
	if pageSize <= 0 {
		return identity.DefaultPageSize
	}
	return pageSize
}
