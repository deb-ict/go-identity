# go-identity

An OAuth 2.0 authorization server and identity provider for Go.

- **RFC 6749 authorization server**: authorization code, implicit, resource owner password
  credentials, client credentials and refresh token grants, plus extension grants.
- **Router independent**: runs on `net/http`, [chi](router/chi), [gin](router/gin),
  [httprouter](router/httprouter), [gorilla/mux](router/gorillamux) or [echo](router/echo),
  or any router you write a 20-line adapter for.
- **Database independent**: in memory, [PostgreSQL, MySQL, SQLite](store/sql) or [MongoDB](store/mongo),
  or any store that implements `store.Store` and passes the conformance suite.
- **User interface**: login, logout, registration, account activation, password reset and the OAuth consent page.
- **Management API**: a JSON API to manage clients, users, access tokens and refresh tokens.

The core module only depends on `golang.org/x/crypto`. Router adapters, database stores and
the server binary are separate Go modules, so you only pull in what you use.

## Contents

- [Quick start](#quick-start)
- [Using it as a library](#using-it-as-a-library)
- [Standards](#standards)
- [Endpoints](#endpoints)
- [Management API](#management-api)
- [Configuration](#configuration)
- [Security](#security)
- [Repository layout](#repository-layout)
- [Development](#development)

## Quick start

```sh
cd cmd/identity-server
go run . \
  -public-url http://localhost:8080 \
  -session-key "$(openssl rand -hex 32)" \
  -admin-client-id admin -admin-client-secret "$(openssl rand -hex 16)" \
  -allow-registration
```

Open http://localhost:8080/register to create an account. Without SMTP settings, the
activation email is written to the log.

Then get a token for the management API:

```sh
curl -u admin:<secret> -d grant_type=client_credentials http://localhost:8080/token
```

Choose the router with `-router` (`std`, `chi`, `gin`, `httprouter`, `gorillamux`, `echo`)
and the database with `-db-driver` / `-db-dsn`:

```sh
go run . -db-driver postgres -db-dsn "postgres://user:pass@localhost:5432/identity"
go run . -db-driver mysql    -db-dsn "user:pass@tcp(localhost:3306)/identity"
go run . -db-driver sqlite   -db-dsn "file:identity.db"
go run . -db-driver mongo    -db-dsn "mongodb://localhost:27017" -db-name identity
```

The schema (or the MongoDB indexes) is created at startup.

## Using it as a library

```go
import (
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/server"
	"github.com/deb-ict/go-identity/pkg/store/memory"
)

srv, err := server.New(server.Config{
	Store:      memory.New(),                        // or sqlstore / mongostore
	PublicURL:  "https://example.com/identity",      // issuer; the path becomes the base path
	SessionKey: sessionKey,                          // >= 32 bytes, same on every instance
	Mailer:     mail.NewSMTPSender(mail.SMTPConfig{ /* ... */ }),
	AllowRegistration: true,
})

mux := router.NewServeMux()
srv.RegisterRoutes(mux)
http.ListenAndServe(":8080", mux)
```

### Any router

`server.RegisterRoutes` takes a `router.Router`:

```go
type Router interface {
	Handle(method string, pattern string, handler http.Handler)
}
```

Patterns use `{name}` placeholders (`/api/clients/{id}`) and handlers read them with
`router.Param(r, "id")`. The adapters translate that to the router's own syntax:

```go
r := chi.NewRouter()
srv.RegisterRoutes(chirouter.New(r))

engine := gin.New()
srv.RegisterRoutes(ginrouter.New(engine))

e := echo.New()
srv.RegisterRoutes(echorouter.New(e))
```

To support another router, implement `Handle`: convert the pattern (see
`router.ColonPattern`), and pass the path parameters to the handler with
`router.WithParams`. Run `routertest.Run` from `pkg/router/routertest` to check it. See
[router/README.md](router/README.md).

### Any database

Everything is persisted through `store.Store` (`pkg/store`), a set of small interfaces for
clients, users, access tokens, refresh tokens, authorization codes and one-time user tokens.

```go
db, _ := sql.Open("pgx", dsn)
s, _ := sqlstore.New(db, sqlstore.Options{Dialect: sqlstore.DialectPostgres})
s.Migrate(ctx)

client, _ := mongo.Connect(options.Client().ApplyURI(uri))
s := mongostore.New(client.Database("identity"), mongostore.Options{})
s.EnsureIndexes(ctx)
```

A custom store must pass the conformance suite:

```go
func TestStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return newEmptyStore(t) })
}
```

See [store/sql/README.md](store/sql/README.md) and [store/mongo/README.md](store/mongo/README.md).

### Building blocks

`server` only wires the packages together. You can also use them on their own:

| Package | Purpose |
| --- | --- |
| `pkg/oauth` | Authorization server: endpoints, grants, client authentication, `RequireBearer` middleware, `RegisterGrant` for extension grants, pluggable `TokenGenerator` (e.g. JWT) |
| `pkg/account` | Registration, activation, authentication with lockout, password reset, user administration |
| `pkg/ui` | HTML pages; implements `oauth.Interaction`. Templates can be overridden with `Config.Templates` |
| `pkg/api` | Management API |
| `pkg/session` | Signed session cookie and CSRF protection |
| `pkg/mail` | `mail.Sender` with SMTP, log and in-memory implementations |
| `pkg/security` | bcrypt hashing, random tokens, PKCE |

To protect your own API with tokens from this server:

```go
mux.Handle("GET /orders", srv.OAuth.RequireBearer("orders.read")(ordersHandler))

// in the handler
info, _ := oauth.TokenFromContext(r.Context()) // info.Client, info.User, info.Token.Scopes
```

Resource servers running elsewhere can use the introspection endpoint.

## Standards

| Specification | Supported |
| --- | --- |
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) OAuth 2.0 | Authorization endpoint (GET and POST), token endpoint, `code` and `token` response types, `authorization_code`, `password`, `client_credentials` and `refresh_token` grants, extension grants, `client_secret_basic` and `client_secret_post` client authentication, public clients, redirect URI validation, `state`, scopes, error responses |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) Bearer tokens | `Authorization: Bearer` validation with `WWW-Authenticate` errors (`invalid_token`, `insufficient_scope`) |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE | `S256` and `plain`; required for public clients, optional per client (`require_pkce`) |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) Token revocation | Access and refresh tokens; revoking a refresh token revokes its access token |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) Token introspection | For confidential clients |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) Server metadata | `/.well-known/oauth-authorization-server` below the base path |

Behaviour worth knowing:

- Parameters sent more than once are rejected. The token endpoint only reads the request body.
- An authorization code is valid for 5 minutes by default (at most 10) and can be used once. If
  it is used a second time, every token issued for it is revoked (section 4.1.2).
- Without `redirect_uri`, the client must have exactly one registered URI. Redirect URIs are
  compared as exact strings, and the query of a registered URI is kept.
- Errors about the client or the redirect URI are shown to the user; all other errors are
  sent to the client (in the fragment for the implicit grant).
- The client credentials and implicit grants never issue refresh tokens. Other grants issue one
  when the client may use the `refresh_token` grant.
- Refresh tokens are either `reuse` (the same token, and the response doesn't repeat it) or
  `onetime` (rotated on every use). Expiration is either `sliding` or `absolute`; an absolute
  lifetime is kept across rotations. A refresh request may narrow the scope but never widen it.
- When the scope is omitted, the client's `default_scopes` are used.

## Endpoints

Every path is relative to the base path, which is the path of `PublicURL`.

| Method | Path | Description |
| --- | --- | --- |
| GET, POST | `/authorize` | Authorization endpoint |
| POST | `/token` | Token endpoint |
| POST | `/revoke` | Token revocation |
| POST | `/introspect` | Token introspection |
| GET | `/.well-known/oauth-authorization-server` | Server metadata |
| GET | `/` | Account page when signed in |
| GET, POST | `/login` | Sign in; `return_to` must be a local path |
| GET, POST | `/logout` | Sign out |
| GET, POST | `/register` | Self registration (when `AllowRegistration` is set) |
| GET | `/activate?token=` | Account activation link |
| GET, POST | `/activation/resend` | Request a new activation email |
| GET, POST | `/password/forgot` | Request a password reset email |
| GET, POST | `/password/reset?token=` | Choose a new password |
| * | `/api/...` | [Management API](#management-api) |

### Flows

- **Login**: `/authorize` sends a signed-out user to `/login?return_to=…`. After signing in,
  the user returns to the authorization request. If the client has `require_consent` set, the
  consent page asks the user to allow or deny.
- **Activation**: a registered user gets an email with an activation link, valid for 48 hours.
  Until the account is activated, sign-in and the password grant are refused (unless
  `DisableActivation` is set). A new link can be requested at `/activation/resend`.
- **Password reset**: `/password/forgot` emails a link that is valid for 1 hour. Setting a new
  password also confirms the email address, unlocks the account, revokes all tokens and ends
  every session.

Forms that tell whether an email address has an account (`/password/forgot` and
`/activation/resend`) always give the same answer.

## Management API

The API requires a bearer token with the `identity.admin` scope (`Config.AdminScope`). The
usual way to get one is the client credentials grant with an admin client; the server binary
creates that client from `-admin-client-id` and `-admin-client-secret`.

Requests and responses are JSON. Lists take `offset` and `limit` (default 50, max 500) and
return `{"items": [...], "total": n, "offset": o, "limit": l}`. Errors look like
`{"error": "validation_failed", "error_description": "...", "field": "redirect_uris"}`.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/clients` | List clients |
| POST | `/api/clients` | Create a client. For a confidential client the response has a generated `client_secret`; it is shown only once |
| GET | `/api/clients/{id}` | Get a client |
| PUT | `/api/clients/{id}` | Replace a client. Disabling a client revokes its tokens |
| DELETE | `/api/clients/{id}` | Delete a client and its tokens |
| POST | `/api/clients/{id}/secret` | Generate a new client secret |
| GET | `/api/users?search=` | List users; searches username and email |
| POST | `/api/users` | Create a user. `password` is optional; `send_activation` sends the activation email |
| GET | `/api/users/{id}` | Get a user |
| PUT | `/api/users/{id}` | Update `username`, `email`, `email_verified` and `enabled`. Disabling a user revokes their tokens |
| DELETE | `/api/users/{id}` | Delete a user and their tokens |
| POST | `/api/users/{id}/password` | Set the password; revokes the user's tokens and sessions |
| POST | `/api/users/{id}/unlock` | Clear a lockout |
| POST | `/api/users/{id}/activation` | Send the activation email |
| POST | `/api/users/{id}/password-reset` | Send the password reset email |
| DELETE | `/api/users/{id}/tokens` | Revoke all tokens of a user |
| GET | `/api/tokens?client_id=&user_id=&expired=` | List access tokens |
| GET | `/api/tokens/{id}` | Get an access token |
| DELETE | `/api/tokens/{id}` | Revoke an access token |
| DELETE | `/api/tokens?client_id=&user_id=&expired=` | Revoke matching access tokens; a filter is required |
| GET, DELETE | `/api/refresh-tokens[/{id}]` | The same for refresh tokens; deleting one also revokes its access token |

Token values are never stored or returned, only their SHA-256 hash is kept. In token
resources, `client_id` is the `id` of the client resource.

Example: create a client for a single page application.

```sh
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
        "client_id": "spa",
        "name": "My App",
        "type": "public",
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "allowed_scopes": ["profile", "orders.read"],
        "require_consent": true,
        "refresh_token_usage": "onetime"
      }' \
  http://localhost:8080/api/clients
```

Client fields: `client_id`, `name`, `description`, `type` (`confidential` or `public`),
`redirect_uris`, `allowed_scopes`, `default_scopes`, `grant_types` (`authorization_code`,
`implicit`, `password`, `client_credentials`, `refresh_token` or an extension grant URI),
`require_consent`, `require_pkce`, `enabled`, `access_token_lifetime`,
`authorization_code_lifetime`, `refresh_token_lifetime` (lifetimes in seconds; 0 means the
default), `refresh_token_usage` (`reuse`, `onetime`) and `refresh_token_expiration`
(`sliding`, `absolute`).

## Configuration

`server.Config` fields, and the matching `identity-server` flags. Each flag can also be set
with the environment variable in brackets.

| Config | Flag [env] | Default | Description |
| --- | --- | --- | --- |
| `Store` | `-db-driver`, `-db-dsn`, `-db-name` [`IDENTITY_DB_*`] | `memory` | Storage |
| `PublicURL` | `-public-url` [`IDENTITY_PUBLIC_URL`] | `http://localhost:8080` | External URL; used as issuer and for email links |
| `BasePath` | `-base-path` [`IDENTITY_BASE_PATH`] | path of `PublicURL` | Route prefix; set it when a proxy rewrites the path |
| `SessionKey` | `-session-key` [`IDENTITY_SESSION_KEY`] | random | Cookie signing key, at least 32 bytes |
| `ApplicationName` | `-app-name` [`IDENTITY_APP_NAME`] | `Identity` | Shown in the UI and emails |
| `AllowRegistration` | `-allow-registration` | `false` | Allow self registration |
| `DisableActivation` | `-disable-activation` | `false` | Let users sign in without confirming their email |
| `Mailer` | `-smtp-host`, `-smtp-port`, `-smtp-username`, `-smtp-password`, `-smtp-from`, `-smtp-implicit-tls` | log | Email delivery; STARTTLS is used when the server offers it |
| `MaxFailedAttempts` / `LockoutDuration` | | 5 / 15 min | Account lockout |
| `MinPasswordLength` | | 8 | Password policy |
| `AdminScope` | | `identity.admin` | Scope the management API requires |
| `Templates` | | embedded | Override the UI templates (`fs.FS`, see `pkg/ui/templates`) |
| `TokenGenerator` | | opaque | Access token format |
| | `-router` [`IDENTITY_ROUTER`] | `std` | `std`, `chi`, `gin`, `httprouter`, `gorillamux`, `echo` |
| | `-admin-client-id`, `-admin-client-secret` | | Create or update the admin client at startup |
| | `-cleanup-interval` | 15m | How often expired tokens are deleted |

## Security

- Passwords and client secrets are hashed with bcrypt. Because bcrypt ignores everything after
  72 bytes, longer secrets are refused rather than silently truncated.
- Access tokens, refresh tokens, authorization codes and email tokens are random 256-bit values.
  Only their SHA-256 hash is stored.
- Authorization codes are consumed atomically in every store, so two simultaneous requests can't
  both exchange the same code.
- Sessions are HMAC-signed, `HttpOnly`, `SameSite=Lax` cookies. They are `Secure` when the public
  URL uses https, and are limited to the base path. A session carries the user's security stamp,
  which changes when the password changes or the account is disabled; that ends the session.
- Every form is CSRF protected (signed double submit cookie), including the consent form.
- Pages are sent with `Content-Security-Policy`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` (reset links don't leak) and `Cache-Control: no-store`.
- Only local `return_to` targets are allowed, so the login page can't be used as an open redirect.
- Login and the password grant check the password before they say whether an account is
  locked, disabled or not activated. Unknown users and clients take as long to reject as
  wrong passwords.
- After 5 consecutive failures, an account is locked for 15 minutes.

## Repository layout

```
pkg/                      core module github.com/deb-ict/go-identity
  identity/               domain model: clients, users, tokens, scopes
  store/                  storage interfaces; memory/ implementation; storetest/ conformance suite
  router/                 router abstraction + net/http ServeMux adapter; routertest/ conformance suite
  oauth/                  RFC 6749 authorization server
  account/                user account flows
  session/  mail/  security/
  ui/                     HTML pages (templates/ embedded)
  api/                    management API
  server/                 wires everything together
router/{chi,gin,httprouter,gorillamux,echo}   router adapter modules
store/sql                 PostgreSQL / MySQL / SQLite module
store/mongo               MongoDB module
cmd/identity-server       server binary module
```

## Development

The repository is a Go workspace (`go.work`); every module has its own `go.mod`.

```sh
go test ./...                                  # core module
for m in cmd/identity-server router/* store/*; do (cd $m && go test ./...); done
```

The SQL and MongoDB tests run the conformance suite against real databases when these are set:

```sh
export IDENTITY_TEST_POSTGRES_DSN="postgres://identity:identity@localhost:5432/identity_test?sslmode=disable"
export IDENTITY_TEST_MYSQL_DSN="root:root@tcp(localhost:3306)/identity_test"
export IDENTITY_TEST_MONGO_URI="mongodb://localhost:27017"
```

SQLite always runs, using a pure Go driver. CI tests every module against PostgreSQL 16,
MySQL 8.4 and MongoDB 7.
