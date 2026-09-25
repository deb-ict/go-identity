# mongostore

MongoDB implementation of `store.Store` for [go-identity](https://github.com/deb-ict/go-identity).
It uses the official driver `go.mongodb.org/mongo-driver/v2`.

```sh
go get github.com/deb-ict/go-identity/store/mongo
```

## Usage

```go
import (
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	mongostore "github.com/deb-ict/go-identity/store/mongo"
)

client, err := mongo.Connect(options.Client().ApplyURI("mongodb://localhost:27017"))
if err != nil {
	return err
}
defer client.Disconnect(ctx)

s := mongostore.New(client.Database("identity"), mongostore.Options{
	CollectionPrefix: "identity_", // the default
})

// Creates the unique and helper indexes. Safe to call on every start-up.
if err := s.EnsureIndexes(ctx); err != nil {
	return err
}
```

`EnsureIndexes` must run before the store is used: the unique constraints on the client id,
normalized username, normalized email, token hashes and code hash are enforced by unique indexes.

## Collections

| Collection                    | Unique indexes                                   |
| ----------------------------- | ------------------------------------------------ |
| `<prefix>clients`             | `client_id`                                      |
| `<prefix>users`               | `normalized_username`, `normalized_email`        |
| `<prefix>access_tokens`       | `token_hash`                                     |
| `<prefix>refresh_tokens`      | `token_hash`                                     |
| `<prefix>authorization_codes` | `code_hash`                                      |
| `<prefix>user_tokens`         | `token_hash`                                     |

The `_id` of every document is the entity id. Times are stored as BSON datetimes (millisecond
precision, returned in UTC), durations as int64 nanoseconds.

## Tests

The unit tests run without a server. The conformance suite (`pkg/store/storetest`) runs when
`IDENTITY_TEST_MONGO_URI` is set; every sub-test uses a fresh database that is dropped afterwards.

```sh
docker run -d --rm -p 27017:27017 mongo:7
IDENTITY_TEST_MONGO_URI=mongodb://localhost:27017 go test ./...
```
