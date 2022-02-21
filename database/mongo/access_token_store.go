package mongo

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type accessTokenDocument struct {
	Id         primitive.ObjectID `bson:"_id,omitempty"`
	ClientId   primitive.ObjectID `bson:"clientId"`
	SubjectId  primitive.ObjectID `bson:"subjectId"`
	TokenType  string             `bson:"tokenType"`
	TokenValue string             `bson:"tokenValue"`
	CreatedAt  time.Time          `bson:"createdAt"`
	Lifetime   time.Duration      `bons:"lifetime"`
}

type accessTokenStore struct {
	db         *database
	collection *mongo.Collection
}
