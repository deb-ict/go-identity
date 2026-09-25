package mongostore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"reflect"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/store"
	"github.com/deb-ict/go-identity/pkg/store/storetest"
)

// TestStore runs the conformance suite. It requires a MongoDB server:
//
//	IDENTITY_TEST_MONGO_URI=mongodb://localhost:27017 go test ./...
func TestStore(t *testing.T) {
	uri := os.Getenv("IDENTITY_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("IDENTITY_TEST_MONGO_URI not set")
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatalf("ping: %v", err)
	}

	storetest.Run(t, func(t *testing.T) store.Store {
		db := client.Database(uniqueDatabaseName(t))
		t.Cleanup(func() { _ = db.Drop(context.Background()) })
		s := New(db, Options{})
		// Twice, to prove EnsureIndexes is idempotent
		for i := 0; i < 2; i++ {
			if err := s.EnsureIndexes(context.Background()); err != nil {
				t.Fatalf("ensure indexes (%d): %v", i, err)
			}
		}
		return s
	})
}

func uniqueDatabaseName(t *testing.T) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return "identity_test_" + hex.EncodeToString(b)
}

// Unit tests that don't need a server

// roundTrip marshals the document to BSON and back, like a real insert and find would.
func roundTrip[D any](t *testing.T, doc *D) *D {
	t.Helper()
	data, err := bson.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var result D
	if err := bson.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &result
}

var (
	// Nanosecond precision and a non-UTC zone, both must be normalized.
	testTime   = time.Date(2024, 1, 2, 3, 4, 5, 6_789_123, time.FixedZone("CET", 3600))
	testTimeMs = time.Date(2024, 1, 2, 2, 4, 5, 6_000_000, time.UTC)
)

func ptr[T any](v T) *T {
	return &v
}

func TestClientRoundTrip(t *testing.T) {
	client := &identity.Client{
		Id:                        "c1",
		ClientId:                  "client-one",
		Name:                      "Client",
		Description:               "Description",
		Type:                      identity.ClientTypePublic,
		SecretHash:                "hash",
		RedirectUris:              []string{"https://example.com/cb"},
		AllowedScopes:             []string{"a", "b"},
		DefaultScopes:             nil,
		AllowedGrantTypes:         []identity.GrantType{identity.GrantTypeAuthorizationCode},
		RequireConsent:            true,
		RequirePkce:               true,
		Enabled:                   true,
		AccessTokenLifetime:       10*time.Minute + 1,
		AuthorizationCodeLifetime: 2 * time.Minute,
		RefreshTokenUsage:         identity.RefreshTokenUsageOneTime,
		RefreshTokenExpiration:    identity.RefreshTokenExpirationAbsolute,
		RefreshTokenLifetime:      48 * time.Hour,
		CreatedAt:                 testTime,
		UpdatedAt:                 testTime,
	}
	got := roundTrip(t, clientToDocument(client)).toModel()

	expected := *client
	expected.DefaultScopes = []string{}
	expected.CreatedAt = testTimeMs
	expected.UpdatedAt = testTimeMs
	if !reflect.DeepEqual(&expected, got) {
		t.Fatalf("mismatch:\nexpected %+v\nactual   %+v", expected, *got)
	}
}

func TestUserRoundTrip(t *testing.T) {
	user := &identity.User{
		Id:               "u1",
		Username:         "Alice",
		Email:            "Alice@Example.com",
		PasswordHash:     "hash",
		EmailVerified:    true,
		Enabled:          true,
		SecurityStamp:    "stamp",
		FailedLoginCount: 3,
		LockoutEnd:       ptr(testTime),
		LastLoginAt:      nil,
		CreatedAt:        testTime,
		UpdatedAt:        testTime,
	}
	user.Normalize()
	doc := roundTrip(t, userToDocument(user))
	got := doc.toModel()

	expected := *user
	expected.LockoutEnd = ptr(testTimeMs)
	expected.CreatedAt = testTimeMs
	expected.UpdatedAt = testTimeMs
	if !reflect.DeepEqual(&expected, got) {
		t.Fatalf("mismatch:\nexpected %+v\nactual   %+v", expected, *got)
	}
}

func TestTokenRoundTrips(t *testing.T) {
	access := &identity.AccessToken{
		Id: "a1", TokenHash: "h", ClientId: "c", UserId: "u", Scopes: []string{"x"},
		AuthorizationCodeId: "code", CreatedAt: testTime, ExpiresAt: testTime,
	}
	gotAccess := roundTrip(t, accessTokenToDocument(access)).toModel()
	expectedAccess := *access
	expectedAccess.CreatedAt, expectedAccess.ExpiresAt = testTimeMs, testTimeMs
	if !reflect.DeepEqual(&expectedAccess, gotAccess) {
		t.Fatalf("access token mismatch:\nexpected %+v\nactual   %+v", expectedAccess, *gotAccess)
	}

	refresh := &identity.RefreshToken{
		Id: "r1", TokenHash: "h", ClientId: "c", UserId: "u", AccessTokenId: "a1", AuthorizationCodeId: "code",
		Scopes: []string{"x", "offline"}, TokenExpiration: identity.RefreshTokenExpirationSliding,
		TokenUsage: identity.RefreshTokenUsageReUse, Lifetime: 24*time.Hour + 5,
		CreatedAt: testTime, UpdatedAt: testTime, ExpiresAt: testTime,
	}
	gotRefresh := roundTrip(t, refreshTokenToDocument(refresh)).toModel()
	expectedRefresh := *refresh
	expectedRefresh.CreatedAt, expectedRefresh.UpdatedAt, expectedRefresh.ExpiresAt = testTimeMs, testTimeMs, testTimeMs
	if !reflect.DeepEqual(&expectedRefresh, gotRefresh) {
		t.Fatalf("refresh token mismatch:\nexpected %+v\nactual   %+v", expectedRefresh, *gotRefresh)
	}

	for _, consumed := range []*time.Time{nil, ptr(testTime)} {
		code := &identity.AuthorizationCode{
			Id: "ac1", CodeHash: "h", ClientId: "c", UserId: "u", Scopes: []string{"x"},
			RedirectUri: "https://example.com/cb", CodeChallenge: "ch", CodeChallengeMethod: "S256",
			CreatedAt: testTime, ExpiresAt: testTime, ConsumedAt: consumed,
		}
		gotCode := roundTrip(t, authorizationCodeToDocument(code)).toModel()
		expectedCode := *code
		expectedCode.CreatedAt, expectedCode.ExpiresAt = testTimeMs, testTimeMs
		if consumed != nil {
			expectedCode.ConsumedAt = ptr(testTimeMs)
		}
		if !reflect.DeepEqual(&expectedCode, gotCode) {
			t.Fatalf("authorization code mismatch:\nexpected %+v\nactual   %+v", expectedCode, *gotCode)
		}
	}

	userToken := &identity.UserToken{
		Id: "t1", UserId: "u", Purpose: identity.UserTokenPurposePasswordReset, TokenHash: "h",
		CreatedAt: testTime, ExpiresAt: testTime,
	}
	gotUserToken := roundTrip(t, userTokenToDocument(userToken)).toModel()
	expectedUserToken := *userToken
	expectedUserToken.CreatedAt, expectedUserToken.ExpiresAt = testTimeMs, testTimeMs
	if !reflect.DeepEqual(&expectedUserToken, gotUserToken) {
		t.Fatalf("user token mismatch:\nexpected %+v\nactual   %+v", expectedUserToken, *gotUserToken)
	}
}

func TestNilTimesAreStoredAsNull(t *testing.T) {
	data, err := bson.Marshal(authorizationCodeToDocument(&identity.AuthorizationCode{Id: "ac1"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	value, err := bson.Raw(data).LookupErr("consumed_at")
	if err != nil {
		t.Fatalf("consumed_at missing: %v", err)
	}
	if value.Type != bson.TypeNull {
		t.Fatalf("expected null, got %v", value.Type)
	}
}

func TestTokenFilter(t *testing.T) {
	if got := tokenFilter(store.TokenFilter{}); len(got) != 0 {
		t.Fatalf("empty filter must match everything, got %v", got)
	}
	before := testTime
	got := tokenFilter(store.TokenFilter{ClientId: "c", UserId: "u", AuthorizationCodeId: "code", ExpiredBefore: &before})
	expected := bson.D{
		{Key: "client_id", Value: "c"},
		{Key: "user_id", Value: "u"},
		{Key: "authorization_code_id", Value: "code"},
		{Key: "expires_at", Value: bson.M{"$lte": testTimeMs}},
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected filter:\nexpected %v\nactual   %v", expected, got)
	}
}

func TestUserFilterEscapesSearch(t *testing.T) {
	if got := userFilter(store.UserFilter{}); len(got) != 0 {
		t.Fatalf("empty search must match everything, got %v", got)
	}
	got := userFilter(store.UserFilter{Search: "A.b*%"})
	expected := bson.D{{Key: "$or", Value: bson.A{
		bson.M{"normalized_username": bson.M{"$regex": `a\.b\*%`}},
		bson.M{"normalized_email": bson.M{"$regex": `a\.b\*%`}},
	}}}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected filter:\nexpected %v\nactual   %v", expected, got)
	}
}

func TestCollectionPrefix(t *testing.T) {
	// Collections are lazily created handles, no server connection is needed.
	client, err := mongo.Connect(options.Client().ApplyURI("mongodb://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	db := client.Database("test")

	if name := New(db, Options{}).clients.Name(); name != "identity_clients" {
		t.Fatalf("unexpected default collection name %q", name)
	}
	if name := New(db, Options{CollectionPrefix: "app_"}).userTokens.Name(); name != "app_user_tokens" {
		t.Fatalf("unexpected prefixed collection name %q", name)
	}
}
