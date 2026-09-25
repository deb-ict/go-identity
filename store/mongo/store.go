// Package mongostore implements store.Store on MongoDB using the official Go driver (v2).
//
//	client, err := mongo.Connect(options.Client().ApplyURI("mongodb://localhost:27017"))
//	s := mongostore.New(client.Database("identity"), mongostore.Options{})
//	if err := s.EnsureIndexes(ctx); err != nil { ... }
package mongostore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/store"
)

var _ store.Store = (*Store)(nil)

// DefaultCollectionPrefix is used when Options.CollectionPrefix is empty.
const DefaultCollectionPrefix = "identity_"

// Collection names, without prefix.
const (
	clientsCollection            = "clients"
	usersCollection              = "users"
	accessTokensCollection       = "access_tokens"
	refreshTokensCollection      = "refresh_tokens"
	authorizationCodesCollection = "authorization_codes"
	userTokensCollection         = "user_tokens"
)

// Options configures the MongoDB store.
type Options struct {
	// CollectionPrefix is prepended to every collection name. Defaults to "identity_".
	CollectionPrefix string
}

// Store is a store.Store backed by a MongoDB database.
type Store struct {
	clients            *mongo.Collection
	users              *mongo.Collection
	accessTokens       *mongo.Collection
	refreshTokens      *mongo.Collection
	authorizationCodes *mongo.Collection
	userTokens         *mongo.Collection
}

// New creates a store on the given database. Call EnsureIndexes before use:
// the unique constraints (client id, username, email, token hashes) rely on the indexes.
func New(db *mongo.Database, opts Options) *Store {
	prefix := opts.CollectionPrefix
	if prefix == "" {
		prefix = DefaultCollectionPrefix
	}
	return &Store{
		clients:            db.Collection(prefix + clientsCollection),
		users:              db.Collection(prefix + usersCollection),
		accessTokens:       db.Collection(prefix + accessTokensCollection),
		refreshTokens:      db.Collection(prefix + refreshTokensCollection),
		authorizationCodes: db.Collection(prefix + authorizationCodesCollection),
		userTokens:         db.Collection(prefix + userTokensCollection),
	}
}

func index(name string, unique bool, keys ...string) mongo.IndexModel {
	d := bson.D{}
	for _, k := range keys {
		d = append(d, bson.E{Key: k, Value: 1})
	}
	opts := options.Index().SetName(name)
	if unique {
		opts.SetUnique(true)
	}
	return mongo.IndexModel{Keys: d, Options: opts}
}

// EnsureIndexes creates the unique and helper indexes. It is idempotent.
func (s *Store) EnsureIndexes(ctx context.Context) error {
	tokenIndexes := []mongo.IndexModel{
		index("token_hash_unique", true, "token_hash"),
		index("client_id", false, "client_id"),
		index("user_id", false, "user_id"),
		index("authorization_code_id", false, "authorization_code_id"),
		index("expires_at", false, "expires_at"),
		index("created_at_id", false, "created_at", "_id"),
	}
	all := []struct {
		coll    *mongo.Collection
		indexes []mongo.IndexModel
	}{
		{s.clients, []mongo.IndexModel{
			index("client_id_unique", true, "client_id"),
			index("created_at_id", false, "created_at", "_id"),
		}},
		{s.users, []mongo.IndexModel{
			index("normalized_username_unique", true, "normalized_username"),
			index("normalized_email_unique", true, "normalized_email"),
			index("created_at_id", false, "created_at", "_id"),
		}},
		{s.accessTokens, tokenIndexes},
		{s.refreshTokens, tokenIndexes},
		{s.authorizationCodes, []mongo.IndexModel{
			index("code_hash_unique", true, "code_hash"),
			index("expires_at", false, "expires_at"),
		}},
		{s.userTokens, []mongo.IndexModel{
			index("token_hash_unique", true, "token_hash"),
			index("user_id_purpose", false, "user_id", "purpose"),
			index("expires_at", false, "expires_at"),
		}},
	}
	for _, c := range all {
		if _, err := c.coll.Indexes().CreateMany(ctx, c.indexes); err != nil {
			return fmt.Errorf("mongostore: create indexes on %s: %w", c.coll.Name(), err)
		}
	}
	return nil
}

// Generic helpers

func wrapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("mongostore: %s: %w", op, store.ErrDuplicate)
	}
	return fmt.Errorf("mongostore: %s: %w", op, err)
}

func findOne[D any](ctx context.Context, coll *mongo.Collection, filter any, op string) (*D, error) {
	var doc D
	err := coll.FindOne(ctx, filter).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr(op, err)
	}
	return &doc, nil
}

func findPage[D any](ctx context.Context, coll *mongo.Collection, filter any, opts store.ListOptions, op string) ([]*D, int, error) {
	opts = opts.Normalize()
	total, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, wrapErr(op, err)
	}
	findOpts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}).
		SetSkip(int64(opts.Offset)).
		SetLimit(int64(opts.Limit))
	cursor, err := coll.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, 0, wrapErr(op, err)
	}
	docs := []*D{}
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, 0, wrapErr(op, err)
	}
	return docs, int(total), nil
}

func insert(ctx context.Context, coll *mongo.Collection, doc any, op string) error {
	_, err := coll.InsertOne(ctx, doc)
	return wrapErr(op, err)
}

func replace(ctx context.Context, coll *mongo.Collection, id string, doc any, op string) error {
	result, err := coll.ReplaceOne(ctx, bson.M{"_id": id}, doc)
	if err != nil {
		return wrapErr(op, err)
	}
	if result.MatchedCount == 0 {
		return store.ErrNotFound
	}
	return nil
}

func deleteById(ctx context.Context, coll *mongo.Collection, id string, op string) error {
	result, err := coll.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return wrapErr(op, err)
	}
	if result.DeletedCount == 0 {
		return store.ErrNotFound
	}
	return nil
}

func deleteMany(ctx context.Context, coll *mongo.Collection, filter any, op string) (int, error) {
	result, err := coll.DeleteMany(ctx, filter)
	if err != nil {
		return 0, wrapErr(op, err)
	}
	return int(result.DeletedCount), nil
}

func toModels[D any, M any](docs []*D, convert func(*D) *M) []*M {
	result := make([]*M, 0, len(docs))
	for _, d := range docs {
		result = append(result, convert(d))
	}
	return result
}

// tokenFilter builds the query for a store.TokenFilter: an AND of the non-empty fields.
func tokenFilter(f store.TokenFilter) bson.D {
	filter := bson.D{}
	if f.ClientId != "" {
		filter = append(filter, bson.E{Key: "client_id", Value: f.ClientId})
	}
	if f.UserId != "" {
		filter = append(filter, bson.E{Key: "user_id", Value: f.UserId})
	}
	if f.AuthorizationCodeId != "" {
		filter = append(filter, bson.E{Key: "authorization_code_id", Value: f.AuthorizationCodeId})
	}
	if f.ExpiredBefore != nil {
		filter = append(filter, bson.E{Key: "expires_at", Value: bson.M{"$lte": toDBTime(*f.ExpiredBefore)}})
	}
	return filter
}

// userFilter builds the query for a store.UserFilter. The search is a literal,
// case insensitive substring match on the normalized username or email.
func userFilter(f store.UserFilter) bson.D {
	if f.Search == "" {
		return bson.D{}
	}
	pattern := regexp.QuoteMeta(strings.ToLower(f.Search))
	return bson.D{{Key: "$or", Value: bson.A{
		bson.M{"normalized_username": bson.M{"$regex": pattern}},
		bson.M{"normalized_email": bson.M{"$regex": pattern}},
	}}}
}

// Clients

func (s *Store) ListClients(ctx context.Context, opts store.ListOptions) ([]*identity.Client, int, error) {
	docs, total, err := findPage[clientDocument](ctx, s.clients, bson.D{}, opts, "list clients")
	if err != nil {
		return nil, 0, err
	}
	return toModels(docs, (*clientDocument).toModel), total, nil
}

func (s *Store) GetClientById(ctx context.Context, id string) (*identity.Client, error) {
	doc, err := findOne[clientDocument](ctx, s.clients, bson.M{"_id": id}, "get client")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) GetClientByClientId(ctx context.Context, clientId string) (*identity.Client, error) {
	doc, err := findOne[clientDocument](ctx, s.clients, bson.M{"client_id": clientId}, "get client by client id")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) CreateClient(ctx context.Context, client *identity.Client) error {
	return insert(ctx, s.clients, clientToDocument(client), "create client")
}

func (s *Store) UpdateClient(ctx context.Context, client *identity.Client) error {
	return replace(ctx, s.clients, client.Id, clientToDocument(client), "update client")
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	return deleteById(ctx, s.clients, id, "delete client")
}

// Users

func (s *Store) ListUsers(ctx context.Context, filter store.UserFilter, opts store.ListOptions) ([]*identity.User, int, error) {
	docs, total, err := findPage[userDocument](ctx, s.users, userFilter(filter), opts, "list users")
	if err != nil {
		return nil, 0, err
	}
	return toModels(docs, (*userDocument).toModel), total, nil
}

func (s *Store) GetUserById(ctx context.Context, id string) (*identity.User, error) {
	doc, err := findOne[userDocument](ctx, s.users, bson.M{"_id": id}, "get user")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) GetUserByNormalizedUsername(ctx context.Context, normalizedUsername string) (*identity.User, error) {
	doc, err := findOne[userDocument](ctx, s.users, bson.M{"normalized_username": normalizedUsername}, "get user by username")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) GetUserByNormalizedEmail(ctx context.Context, normalizedEmail string) (*identity.User, error) {
	doc, err := findOne[userDocument](ctx, s.users, bson.M{"normalized_email": normalizedEmail}, "get user by email")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) CreateUser(ctx context.Context, user *identity.User) error {
	return insert(ctx, s.users, userToDocument(user), "create user")
}

func (s *Store) UpdateUser(ctx context.Context, user *identity.User) error {
	return replace(ctx, s.users, user.Id, userToDocument(user), "update user")
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return deleteById(ctx, s.users, id, "delete user")
}

// Access tokens

func (s *Store) ListAccessTokens(ctx context.Context, filter store.TokenFilter, opts store.ListOptions) ([]*identity.AccessToken, int, error) {
	docs, total, err := findPage[accessTokenDocument](ctx, s.accessTokens, tokenFilter(filter), opts, "list access tokens")
	if err != nil {
		return nil, 0, err
	}
	return toModels(docs, (*accessTokenDocument).toModel), total, nil
}

func (s *Store) GetAccessTokenById(ctx context.Context, id string) (*identity.AccessToken, error) {
	doc, err := findOne[accessTokenDocument](ctx, s.accessTokens, bson.M{"_id": id}, "get access token")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) GetAccessTokenByHash(ctx context.Context, tokenHash string) (*identity.AccessToken, error) {
	doc, err := findOne[accessTokenDocument](ctx, s.accessTokens, bson.M{"token_hash": tokenHash}, "get access token by hash")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) CreateAccessToken(ctx context.Context, token *identity.AccessToken) error {
	return insert(ctx, s.accessTokens, accessTokenToDocument(token), "create access token")
}

func (s *Store) DeleteAccessToken(ctx context.Context, id string) error {
	return deleteById(ctx, s.accessTokens, id, "delete access token")
}

func (s *Store) DeleteAccessTokens(ctx context.Context, filter store.TokenFilter) (int, error) {
	return deleteMany(ctx, s.accessTokens, tokenFilter(filter), "delete access tokens")
}

// Refresh tokens

func (s *Store) ListRefreshTokens(ctx context.Context, filter store.TokenFilter, opts store.ListOptions) ([]*identity.RefreshToken, int, error) {
	docs, total, err := findPage[refreshTokenDocument](ctx, s.refreshTokens, tokenFilter(filter), opts, "list refresh tokens")
	if err != nil {
		return nil, 0, err
	}
	return toModels(docs, (*refreshTokenDocument).toModel), total, nil
}

func (s *Store) GetRefreshTokenById(ctx context.Context, id string) (*identity.RefreshToken, error) {
	doc, err := findOne[refreshTokenDocument](ctx, s.refreshTokens, bson.M{"_id": id}, "get refresh token")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*identity.RefreshToken, error) {
	doc, err := findOne[refreshTokenDocument](ctx, s.refreshTokens, bson.M{"token_hash": tokenHash}, "get refresh token by hash")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) CreateRefreshToken(ctx context.Context, token *identity.RefreshToken) error {
	return insert(ctx, s.refreshTokens, refreshTokenToDocument(token), "create refresh token")
}

func (s *Store) UpdateRefreshToken(ctx context.Context, token *identity.RefreshToken) error {
	return replace(ctx, s.refreshTokens, token.Id, refreshTokenToDocument(token), "update refresh token")
}

func (s *Store) DeleteRefreshToken(ctx context.Context, id string) error {
	return deleteById(ctx, s.refreshTokens, id, "delete refresh token")
}

func (s *Store) DeleteRefreshTokens(ctx context.Context, filter store.TokenFilter) (int, error) {
	return deleteMany(ctx, s.refreshTokens, tokenFilter(filter), "delete refresh tokens")
}

// Authorization codes

func (s *Store) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*identity.AuthorizationCode, error) {
	doc, err := findOne[authorizationCodeDocument](ctx, s.authorizationCodes, bson.M{"code_hash": codeHash}, "get authorization code")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) CreateAuthorizationCode(ctx context.Context, code *identity.AuthorizationCode) error {
	return insert(ctx, s.authorizationCodes, authorizationCodeToDocument(code), "create authorization code")
}

func (s *Store) ConsumeAuthorizationCode(ctx context.Context, id string, consumedAt time.Time) error {
	// The filter only matches an unconsumed code, which makes the update atomic.
	result, err := s.authorizationCodes.UpdateOne(ctx,
		bson.M{"_id": id, "consumed_at": nil},
		bson.M{"$set": bson.M{"consumed_at": toDBTime(consumedAt)}},
	)
	if err != nil {
		return wrapErr("consume authorization code", err)
	}
	if result.MatchedCount > 0 {
		return nil
	}
	count, err := s.authorizationCodes.CountDocuments(ctx, bson.M{"_id": id}, options.Count().SetLimit(1))
	if err != nil {
		return wrapErr("consume authorization code", err)
	}
	if count == 0 {
		return store.ErrNotFound
	}
	return store.ErrConflict
}

func (s *Store) DeleteAuthorizationCode(ctx context.Context, id string) error {
	return deleteById(ctx, s.authorizationCodes, id, "delete authorization code")
}

func (s *Store) DeleteExpiredAuthorizationCodes(ctx context.Context, before time.Time) (int, error) {
	return deleteMany(ctx, s.authorizationCodes, bson.M{"expires_at": bson.M{"$lte": toDBTime(before)}}, "delete expired authorization codes")
}

// User tokens

func (s *Store) GetUserTokenByHash(ctx context.Context, purpose identity.UserTokenPurpose, tokenHash string) (*identity.UserToken, error) {
	doc, err := findOne[userTokenDocument](ctx, s.userTokens, bson.M{"purpose": string(purpose), "token_hash": tokenHash}, "get user token")
	if err != nil {
		return nil, err
	}
	return doc.toModel(), nil
}

func (s *Store) CreateUserToken(ctx context.Context, token *identity.UserToken) error {
	return insert(ctx, s.userTokens, userTokenToDocument(token), "create user token")
}

func (s *Store) DeleteUserToken(ctx context.Context, id string) error {
	return deleteById(ctx, s.userTokens, id, "delete user token")
}

func (s *Store) DeleteUserTokens(ctx context.Context, userId string, purpose identity.UserTokenPurpose) (int, error) {
	return deleteMany(ctx, s.userTokens, bson.M{"user_id": userId, "purpose": string(purpose)}, "delete user tokens")
}

func (s *Store) DeleteExpiredUserTokens(ctx context.Context, before time.Time) (int, error) {
	return deleteMany(ctx, s.userTokens, bson.M{"expires_at": bson.M{"$lte": toDBTime(before)}}, "delete expired user tokens")
}
