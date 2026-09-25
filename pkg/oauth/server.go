// Package oauth implements an OAuth 2.0 authorization server (RFC 6749):
//
//   - the authorization endpoint (section 3.1) with the authorization code (4.1) and implicit (4.2) grants,
//     including PKCE (RFC 7636),
//   - the token endpoint (section 3.2) with the authorization code (4.1), resource owner password
//     credentials (4.3), client credentials (4.4) and refresh token (6) grants, plus extension grants (4.5),
//   - client authentication with client_secret_basic and client_secret_post (2.3.1),
//   - token revocation (RFC 7009), token introspection (RFC 7662), authorization server metadata (RFC 8414),
//   - bearer token validation middleware (RFC 6750).
//
// The endpoints are plain http.Handlers, registered on any router through the router.Router abstraction.
package oauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deb-ict/go-identity/pkg/account"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

// Endpoint paths, relative to the base path.
const (
	PathAuthorize  = "/authorize"
	PathToken      = "/token"
	PathRevoke     = "/revoke"
	PathIntrospect = "/introspect"
	PathMetadata   = "/.well-known/oauth-authorization-server"
)

// TokenTypeBearer is the only access token type issued (RFC 6750).
const TokenTypeBearer = "Bearer"

// ConsentRequest describes the authorization request the user must approve.
type ConsentRequest struct {
	Client *identity.Client
	User   *identity.User
	Scopes []string
	// Action is the URL the consent form posts to.
	Action string
	// Params must be posted back as hidden fields, together with consent=allow or consent=deny.
	Params url.Values
}

// Interaction connects the authorization endpoint to the user interface.
type Interaction interface {
	// CurrentUser returns the authenticated end-user, or nil when nobody is logged in.
	CurrentUser(w http.ResponseWriter, r *http.Request) (*identity.User, error)
	// Login sends the user agent to the login page. After login, the user agent must be sent to returnTo.
	Login(w http.ResponseWriter, r *http.Request, returnTo string)
	// Consent renders the consent page.
	Consent(w http.ResponseWriter, r *http.Request, req *ConsentRequest)
	// VerifyConsent checks the CSRF protection of a posted consent decision.
	VerifyConsent(r *http.Request) bool
	// Error renders an error when the user agent can't be redirected back to the client.
	Error(w http.ResponseWriter, r *http.Request, err *Error)
}

// TokenGenerator generates access token values, e.g. opaque tokens or JWTs.
// The user is nil for the client credentials grant.
type TokenGenerator interface {
	GenerateAccessToken(ctx context.Context, token *identity.AccessToken, client *identity.Client, user *identity.User) (string, error)
}

// OpaqueTokenGenerator generates random opaque access tokens.
type OpaqueTokenGenerator struct{}

func (OpaqueTokenGenerator) GenerateAccessToken(ctx context.Context, token *identity.AccessToken, client *identity.Client, user *identity.User) (string, error) {
	return security.NewToken(), nil
}

// Options configures the authorization server.
type Options struct {
	Store store.Store
	// Accounts authenticates resource owners for the password grant and checks the account status.
	Accounts *account.Service
	// Hasher verifies client secrets.
	Hasher security.PasswordHasher
	// Interaction is required for the authorization endpoint.
	Interaction Interaction
	// Issuer is the public URL of the server including the base path, e.g. https://id.example.com/identity.
	Issuer string
	// BasePath is the path prefix of the endpoints, e.g. "/identity".
	BasePath       string
	TokenGenerator TokenGenerator
	// ScopesSupported is published in the metadata document.
	ScopesSupported []string
	Now             func() time.Time
	Logger          *slog.Logger
}

// Server is the OAuth 2.0 authorization server.
type Server struct {
	opts      Options
	grants    map[identity.GrantType]GrantHandler
	dummyOnce sync.Once
	dummyHash string
}

// New creates the authorization server.
func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errors.New("oauth: store is required")
	}
	if opts.Accounts == nil {
		return nil, errors.New("oauth: account service is required")
	}
	if opts.Hasher == nil {
		opts.Hasher = security.NewBcryptHasher(0)
	}
	if opts.TokenGenerator == nil {
		opts.TokenGenerator = OpaqueTokenGenerator{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	opts.BasePath = strings.TrimSuffix(opts.BasePath, "/")
	opts.Issuer = strings.TrimSuffix(opts.Issuer, "/")

	s := &Server{opts: opts, grants: map[identity.GrantType]GrantHandler{}}
	s.RegisterGrant(identity.GrantTypeAuthorizationCode, GrantHandlerFunc(s.authorizationCodeGrant))
	s.RegisterGrant(identity.GrantTypePassword, GrantHandlerFunc(s.passwordGrant))
	s.RegisterGrant(identity.GrantTypeClientCredentials, GrantHandlerFunc(s.clientCredentialsGrant))
	s.RegisterGrant(identity.GrantTypeRefreshToken, GrantHandlerFunc(s.refreshTokenGrant))
	return s, nil
}

// RegisterGrant registers (or replaces) the handler of a grant type. Extension grants use an absolute URI
// as grant type (RFC 6749 section 4.5).
func (s *Server) RegisterGrant(grantType identity.GrantType, handler GrantHandler) {
	s.grants[grantType] = handler
}

// RegisterRoutes registers the OAuth endpoints. The router must already apply the base path.
func (s *Server) RegisterRoutes(r router.Router) {
	if s.opts.Interaction != nil {
		r.Handle(http.MethodGet, PathAuthorize, http.HandlerFunc(s.HandleAuthorize))
		r.Handle(http.MethodPost, PathAuthorize, http.HandlerFunc(s.HandleAuthorize))
	}
	r.Handle(http.MethodPost, PathToken, http.HandlerFunc(s.HandleToken))
	r.Handle(http.MethodPost, PathRevoke, http.HandlerFunc(s.HandleRevoke))
	r.Handle(http.MethodPost, PathIntrospect, http.HandlerFunc(s.HandleIntrospect))
	r.Handle(http.MethodGet, PathMetadata, http.HandlerFunc(s.HandleMetadata))
}

func (s *Server) now() time.Time {
	return s.opts.Now().UTC().Truncate(time.Millisecond)
}

func (s *Server) serverError(ctx context.Context, msg string, err error) *Error {
	s.opts.Logger.ErrorContext(ctx, msg, "error", err)
	return AsError(err)
}

// Metadata is the authorization server metadata (RFC 8414).
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// Metadata returns the authorization server metadata.
func (s *Server) Metadata() *Metadata {
	grantTypes := []string{string(identity.GrantTypeImplicit)}
	for grantType := range s.grants {
		grantTypes = append(grantTypes, string(grantType))
	}
	sort.Strings(grantTypes)
	m := &Metadata{
		Issuer:                            s.opts.Issuer,
		TokenEndpoint:                     s.opts.Issuer + PathToken,
		RevocationEndpoint:                s.opts.Issuer + PathRevoke,
		IntrospectionEndpoint:             s.opts.Issuer + PathIntrospect,
		ScopesSupported:                   s.opts.ScopesSupported,
		ResponseTypesSupported:            []string{string(identity.ResponseTypeCode), string(identity.ResponseTypeToken)},
		GrantTypesSupported:               grantTypes,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{security.CodeChallengeMethodS256, security.CodeChallengeMethodPlain},
	}
	if s.opts.Interaction != nil {
		m.AuthorizationEndpoint = s.opts.Issuer + PathAuthorize
	}
	return m
}

// HandleMetadata serves the authorization server metadata.
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, s.Metadata())
}
