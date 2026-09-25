package oauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/deb-ict/go-identity/pkg/account"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/oauth"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
	"github.com/deb-ict/go-identity/pkg/store/memory"
)

// fakeInteraction simulates the UI: the logged in user is set by the test.
type fakeInteraction struct {
	user          *identity.User
	consentValid  bool
	loginReturnTo string
	consent       *oauth.ConsentRequest
	err           *oauth.Error
}

func (f *fakeInteraction) CurrentUser(w http.ResponseWriter, r *http.Request) (*identity.User, error) {
	return f.user, nil
}

func (f *fakeInteraction) Login(w http.ResponseWriter, r *http.Request, returnTo string) {
	f.loginReturnTo = returnTo
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (f *fakeInteraction) Consent(w http.ResponseWriter, r *http.Request, req *oauth.ConsentRequest) {
	f.consent = req
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "consent page")
}

func (f *fakeInteraction) VerifyConsent(r *http.Request) bool {
	return f.consentValid
}

func (f *fakeInteraction) Error(w http.ResponseWriter, r *http.Request, err *oauth.Error) {
	f.err = err
	w.WriteHeader(err.Status)
	io.WriteString(w, "error page: "+err.Code)
}

type fixture struct {
	t           *testing.T
	store       *memory.Store
	accounts    *account.Service
	server      *oauth.Server
	handler     http.Handler
	interaction *fakeInteraction
	now         time.Time
	user        *identity.User
	hasher      security.PasswordHasher
}

const (
	confidentialSecret = "s3cr3t"
	redirectUri        = "https://client.example.com/cb"
	// RFC 7636 appendix B
	codeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func newFixture(t *testing.T) *fixture {
	f := &fixture{
		t:           t,
		store:       memory.New(),
		interaction: &fakeInteraction{consentValid: true},
		now:         time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC),
		hasher:      security.NewBcryptHasher(4),
	}
	nowFunc := func() time.Time { return f.now }
	f.accounts = account.New(account.Options{
		Store:             f.store,
		Hasher:            f.hasher,
		RequireActivation: true,
		MaxFailedAttempts: 5,
		Now:               nowFunc,
	})
	var err error
	f.server, err = oauth.New(oauth.Options{
		Store:       f.store,
		Accounts:    f.accounts,
		Hasher:      f.hasher,
		Interaction: f.interaction,
		Issuer:      "https://id.example.com",
		Now:         nowFunc,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := router.NewServeMux()
	f.server.RegisterRoutes(mux)
	protected := f.server.RequireBearer("api.read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := oauth.TokenFromContext(r.Context())
		io.WriteString(w, "hello "+info.Client.ClientId)
	}))
	mux.Handle(http.MethodGet, "/resource", protected)
	f.handler = mux

	f.user, err = f.accounts.CreateUser(context.Background(), account.CreateUserInput{
		Username: "alice", Email: "alice@example.com", Password: "correct horse", EmailVerified: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	f.addClient(&identity.Client{
		ClientId: "confidential",
		Type:     identity.ClientTypeConfidential,
		AllowedGrantTypes: []identity.GrantType{
			identity.GrantTypeAuthorizationCode, identity.GrantTypeClientCredentials,
			identity.GrantTypePassword, identity.GrantTypeRefreshToken,
		},
		RedirectUris:  []string{redirectUri},
		AllowedScopes: []string{"api.read", "api.write"},
		DefaultScopes: []string{"api.read"},
	}, confidentialSecret)
	f.addClient(&identity.Client{
		ClientId:          "public",
		Type:              identity.ClientTypePublic,
		AllowedGrantTypes: []identity.GrantType{identity.GrantTypeAuthorizationCode, identity.GrantTypeImplicit, identity.GrantTypeRefreshToken},
		RedirectUris:      []string{redirectUri, "https://client.example.com/other?keep=1"},
		AllowedScopes:     []string{"api.read"},
		RequireConsent:    true,
		RefreshTokenUsage: identity.RefreshTokenUsageOneTime,
	}, "")
	return f
}

func (f *fixture) addClient(client *identity.Client, secret string) *identity.Client {
	client.Id = "id-" + client.ClientId
	client.Enabled = true
	client.EnsureDefaults()
	if secret != "" {
		hash, _ := f.hasher.Hash(secret)
		client.SecretHash = hash
	}
	if err := client.Validate(); err != nil {
		f.t.Fatal(err)
	}
	if err := f.store.CreateClient(context.Background(), client); err != nil {
		f.t.Fatal(err)
	}
	return client
}

func basic(id string, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

type response struct {
	code   int
	header http.Header
	body   map[string]any
	raw    string
}

func (f *fixture) do(req *http.Request) *response {
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	resp := &response{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		json.Unmarshal(rec.Body.Bytes(), &resp.body)
	}
	return resp
}

func (f *fixture) post(path string, form url.Values, auth string) *response {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return f.do(req)
}

func (f *fixture) token(form url.Values, auth string) *response {
	return f.post("/token", form, auth)
}

func (f *fixture) authorize(method string, params url.Values) *response {
	var req *http.Request
	if method == http.MethodGet {
		req = httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(params.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return f.do(req)
}

func (r *response) str(key string) string {
	v, _ := r.body[key].(string)
	return v
}

func expectError(t *testing.T, r *response, status int, code string) {
	t.Helper()
	if r.code != status || r.str("error") != code {
		t.Fatalf("expected %d %s, got %d %s", status, code, r.code, r.raw)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("expected Cache-Control: no-store")
	}
}

func expectTokens(t *testing.T, r *response, refresh bool) {
	t.Helper()
	if r.code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", r.code, r.raw)
	}
	if r.str("access_token") == "" || r.str("token_type") != "Bearer" || r.body["expires_in"] != float64(3600) {
		t.Fatalf("unexpected token response %s", r.raw)
	}
	if (r.str("refresh_token") != "") != refresh {
		t.Fatalf("refresh token presence mismatch (expected %v): %s", refresh, r.raw)
	}
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" {
		t.Fatal("token responses must not be cached")
	}
	if !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
		t.Fatal("expected JSON")
	}
}

func location(t *testing.T, r *response) *url.URL {
	t.Helper()
	if r.code != http.StatusFound {
		t.Fatalf("expected redirect, got %d %s", r.code, r.raw)
	}
	u, err := url.Parse(r.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Token endpoint & client authentication (RFC 6749 section 2.3 and 3.2)

func TestTokenEndpointRequestValidation(t *testing.T) {
	f := newFixture(t)
	form := url.Values{"grant_type": {"client_credentials"}}

	// Content type
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"grant_type":"client_credentials"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", basic("confidential", confidentialSecret))
	expectError(t, f.do(req), 400, "invalid_request")

	// Method
	if r := f.do(httptest.NewRequest(http.MethodGet, "/token", nil)); r.code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", r.code)
	}

	// Missing grant type
	expectError(t, f.token(url.Values{}, basic("confidential", confidentialSecret)), 400, "invalid_request")
	// Duplicate parameter
	expectError(t, f.token(url.Values{"grant_type": {"client_credentials", "password"}}, basic("confidential", confidentialSecret)), 400, "invalid_request")
	// Unknown grant type
	expectError(t, f.token(url.Values{"grant_type": {"urn:unknown"}}, basic("confidential", confidentialSecret)), 400, "unsupported_grant_type")
	// Not allowed for the client
	expectError(t, f.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"public"}}, ""), 400, "unauthorized_client")

	// Credentials in the query string are ignored
	req = httptest.NewRequest(http.MethodPost, "/token?client_id=confidential&client_secret="+confidentialSecret, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	expectError(t, f.do(req), 401, "invalid_client")

	// Charset parameter in the content type is accepted
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Authorization", basic("confidential", confidentialSecret))
	expectTokens(t, f.do(req), false)
}

func TestClientAuthentication(t *testing.T) {
	f := newFixture(t)
	form := func(extra ...string) url.Values {
		v := url.Values{"grant_type": {"client_credentials"}}
		for i := 0; i < len(extra); i += 2 {
			v.Set(extra[i], extra[i+1])
		}
		return v
	}

	// client_secret_basic
	expectTokens(t, f.token(form(), basic("confidential", confidentialSecret)), false)
	// client_secret_post
	expectTokens(t, f.token(form("client_id", "confidential", "client_secret", confidentialSecret), ""), false)

	r := f.token(form(), basic("confidential", "wrong"))
	expectError(t, r, 401, "invalid_client")
	if !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Basic") {
		t.Fatal("expected WWW-Authenticate header")
	}
	expectError(t, f.token(form("client_id", "confidential", "client_secret", "wrong"), ""), 401, "invalid_client")
	expectError(t, f.token(form("client_id", "confidential"), ""), 401, "invalid_client")
	expectError(t, f.token(form(), basic("unknown", "x")), 401, "invalid_client")
	expectError(t, f.token(form(), ""), 401, "invalid_client")
	expectError(t, f.token(form(), "Bearer abc"), 401, "invalid_client")
	// Two authentication methods
	expectError(t, f.token(form("client_secret", confidentialSecret), basic("confidential", confidentialSecret)), 400, "invalid_request")
	// Mismatching client_id
	expectError(t, f.token(form("client_id", "public"), basic("confidential", confidentialSecret)), 400, "invalid_request")
	// Public client with a secret
	expectError(t, f.token(form(), basic("public", "anything")), 401, "invalid_client")

	// Disabled client
	client, _ := f.store.GetClientByClientId(context.Background(), "confidential")
	client.Enabled = false
	f.store.UpdateClient(context.Background(), client)
	expectError(t, f.token(form(), basic("confidential", confidentialSecret)), 401, "invalid_client")
}

func TestClientAuthenticationEncodedCredentials(t *testing.T) {
	f := newFixture(t)
	f.addClient(&identity.Client{
		ClientId:          "client with:colon",
		AllowedGrantTypes: []identity.GrantType{identity.GrantTypeClientCredentials},
	}, "p@ss:wörd")
	expectTokens(t, f.token(url.Values{"grant_type": {"client_credentials"}}, basic("client with:colon", "p@ss:wörd")), false)
}

// Client credentials grant (RFC 6749 section 4.4)

func TestClientCredentialsGrant(t *testing.T) {
	f := newFixture(t)
	auth := basic("confidential", confidentialSecret)

	r := f.token(url.Values{"grant_type": {"client_credentials"}}, auth)
	expectTokens(t, r, false)
	if r.str("scope") != "api.read" {
		t.Fatalf("expected default scope, got %q", r.str("scope"))
	}

	r = f.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"api.write api.read api.write"}}, auth)
	expectTokens(t, r, false)
	if r.str("scope") != "api.write api.read" {
		t.Fatalf("unexpected scope %q", r.str("scope"))
	}

	expectError(t, f.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"admin"}}, auth), 400, "invalid_scope")
	expectError(t, f.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"api.read \"x"}}, auth), 400, "invalid_scope")

	// The token works on a protected resource
	r = f.token(url.Values{"grant_type": {"client_credentials"}}, auth)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+r.str("access_token"))
	if res := f.do(req); res.code != 200 || res.raw != "hello confidential" {
		t.Fatalf("unexpected resource response %d %s", res.code, res.raw)
	}
}

// Resource owner password credentials grant (RFC 6749 section 4.3)

func TestPasswordGrant(t *testing.T) {
	f := newFixture(t)
	auth := basic("confidential", confidentialSecret)
	form := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct horse"}, "scope": {"api.read api.write"}}

	r := f.token(form, auth)
	expectTokens(t, r, true)
	if r.str("scope") != "api.read api.write" {
		t.Fatalf("unexpected scope %q", r.str("scope"))
	}
	tokens, _, _ := f.store.ListAccessTokens(context.Background(), store.TokenFilter{UserId: f.user.Id}, store.ListOptions{})
	if len(tokens) != 1 || tokens[0].ClientId != "id-confidential" {
		t.Fatal("expected an access token for the user")
	}

	bad := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"wrong"}}
	expectError(t, f.token(bad, auth), 400, "invalid_grant")
	expectError(t, f.token(url.Values{"grant_type": {"password"}, "username": {"alice"}}, auth), 400, "invalid_request")
	expectError(t, f.token(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct horse"}, "scope": {"nope"}}, auth), 400, "invalid_scope")

	// Not activated
	f.accounts.CreateUser(context.Background(), account.CreateUserInput{Username: "bob", Email: "bob@example.com", Password: "correct horse", Enabled: true})
	expectError(t, f.token(url.Values{"grant_type": {"password"}, "username": {"bob"}, "password": {"correct horse"}}, auth), 400, "invalid_grant")

	// Lockout after failed attempts
	for i := 0; i < 5; i++ {
		f.token(bad, auth)
	}
	r = f.token(form, auth)
	expectError(t, r, 400, "invalid_grant")
	if !strings.Contains(r.str("error_description"), "locked") {
		t.Fatalf("expected lockout, got %s", r.raw)
	}
}

// Authorization code grant (RFC 6749 section 4.1)

func (f *fixture) authorizeCode(t *testing.T, params url.Values) string {
	t.Helper()
	f.interaction.user = f.user
	u := location(t, f.authorize(http.MethodGet, params))
	if u.Query().Get("error") != "" {
		t.Fatalf("unexpected error %s", u)
	}
	return u.Query().Get("code")
}

func TestAuthorizationCodeGrant(t *testing.T) {
	f := newFixture(t)
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"confidential"},
		"redirect_uri":  {redirectUri},
		"scope":         {"api.read api.write"},
		"state":         {"xyz"},
	}

	// Not logged in: send to the login page and resume afterwards
	r := f.authorize(http.MethodGet, params)
	if r.code != http.StatusFound || r.header.Get("Location") != "/login" {
		t.Fatalf("expected login redirect, got %d %s", r.code, r.header.Get("Location"))
	}
	resume, _ := url.Parse(f.interaction.loginReturnTo)
	if resume.Path != "/authorize" || resume.Query().Get("state") != "xyz" || resume.Query().Get("client_id") != "confidential" {
		t.Fatalf("unexpected return url %s", f.interaction.loginReturnTo)
	}

	// Logged in, no consent required for this client
	f.interaction.user = f.user
	u := location(t, f.authorize(http.MethodGet, params))
	if u.Scheme+"://"+u.Host+u.Path != redirectUri || u.Query().Get("state") != "xyz" || u.Query().Get("code") == "" {
		t.Fatalf("unexpected redirect %s", u)
	}
	code := u.Query().Get("code")
	auth := basic("confidential", confidentialSecret)

	// redirect_uri is required when it was part of the authorization request
	expectError(t, f.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}}, auth), 400, "invalid_grant")
	expectError(t, f.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://evil.example.com"}}, auth), 400, "invalid_grant")
	expectError(t, f.token(url.Values{"grant_type": {"authorization_code"}, "code": {"unknown"}, "redirect_uri": {redirectUri}}, auth), 400, "invalid_grant")

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectUri}}
	r = f.token(form, auth)
	expectTokens(t, r, true)
	if r.str("scope") != "api.read api.write" {
		t.Fatalf("unexpected scope %q", r.str("scope"))
	}
	accessToken := r.str("access_token")

	// The code can only be used once, a second attempt revokes the issued tokens
	expectError(t, f.token(form, auth), 400, "invalid_grant")
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if res := f.do(req); res.code != http.StatusUnauthorized {
		t.Fatalf("tokens must be revoked after code reuse, got %d", res.code)
	}
}

func TestAuthorizationCodeBoundToClientAndExpires(t *testing.T) {
	f := newFixture(t)
	f.addClient(&identity.Client{
		ClientId:          "other",
		AllowedGrantTypes: []identity.GrantType{identity.GrantTypeAuthorizationCode},
		RedirectUris:      []string{redirectUri},
		AllowedScopes:     []string{"api.read"},
	}, "other-secret")

	code := f.authorizeCode(t, url.Values{"response_type": {"code"}, "client_id": {"confidential"}})
	// Code issued to another client
	expectError(t, f.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}}, basic("other", "other-secret")), 400, "invalid_grant")

	// The redirect_uri was omitted (single registered URI), so it's optional in the token request
	f.now = f.now.Add(6 * time.Minute)
	expectError(t, f.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}}, basic("confidential", confidentialSecret)), 400, "invalid_grant")

	f.now = f.now.Add(-6 * time.Minute)
	expectTokens(t, f.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}}, basic("confidential", confidentialSecret)), true)
}

func TestAuthorizationCodeWithPkceAndConsent(t *testing.T) {
	f := newFixture(t)
	f.interaction.user = f.user
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"public"},
		"redirect_uri":          {redirectUri},
		"state":                 {"abc"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	// Public clients must use PKCE
	noPkce := url.Values{"response_type": {"code"}, "client_id": {"public"}, "redirect_uri": {redirectUri}, "state": {"abc"}}
	u := location(t, f.authorize(http.MethodGet, noPkce))
	if u.Query().Get("error") != "invalid_request" || u.Query().Get("state") != "abc" {
		t.Fatalf("expected invalid_request, got %s", u)
	}
	bad := url.Values{}
	for k, v := range params {
		bad[k] = v
	}
	bad.Set("code_challenge_method", "MD5")
	if u := location(t, f.authorize(http.MethodGet, bad)); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("expected invalid_request for unsupported method, got %s", u)
	}

	// The consent page is shown
	r := f.authorize(http.MethodGet, params)
	if r.code != 200 || f.interaction.consent == nil {
		t.Fatalf("expected consent page, got %d %s", r.code, r.raw)
	}
	consent := f.interaction.consent
	if consent.Client.ClientId != "public" || consent.User.Id != f.user.Id || consent.Action != "/authorize" || consent.Params.Get("code_challenge") != codeChallenge {
		t.Fatalf("unexpected consent request %+v", consent)
	}

	// Deny
	deny := url.Values{}
	for k, v := range consent.Params {
		deny[k] = v
	}
	deny.Set("consent", "deny")
	u = location(t, f.authorize(http.MethodPost, deny))
	if u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "abc" {
		t.Fatalf("expected access_denied, got %s", u)
	}

	// Invalid CSRF token
	allow := url.Values{}
	for k, v := range consent.Params {
		allow[k] = v
	}
	allow.Set("consent", "allow")
	f.interaction.consentValid = false
	if r := f.authorize(http.MethodPost, allow); r.code != 400 || f.interaction.err == nil {
		t.Fatalf("expected an error page, got %d", r.code)
	}
	f.interaction.consentValid = true

	// Consent via GET is not possible
	if r := f.authorize(http.MethodGet, allow); r.code != 200 || r.raw != "consent page" {
		t.Fatalf("consent must be posted, got %d %s", r.code, r.raw)
	}

	// Allow
	u = location(t, f.authorize(http.MethodPost, allow))
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("expected a code, got %s", u)
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectUri}, "client_id": {"public"}}
	expectError(t, f.token(form, ""), 400, "invalid_grant") // missing verifier
	form.Set("code_verifier", strings.Repeat("a", 43))
	expectError(t, f.token(form, ""), 400, "invalid_grant") // wrong verifier

	// The wrong verifier didn't consume the code
	form.Set("code_verifier", codeVerifier)
	r = f.token(form, "")
	expectTokens(t, r, true)

	// One-time refresh tokens are rotated
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.str("refresh_token")}, "client_id": {"public"}}
	r2 := f.token(refresh, "")
	expectTokens(t, r2, true)
	if r2.str("refresh_token") == r.str("refresh_token") {
		t.Fatal("expected a new refresh token")
	}
	expectError(t, f.token(refresh, ""), 400, "invalid_grant")
}

func TestPkceVerifierWithoutChallenge(t *testing.T) {
	f := newFixture(t)
	code := f.authorizeCode(t, url.Values{"response_type": {"code"}, "client_id": {"confidential"}})
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {codeVerifier}}
	expectError(t, f.token(form, basic("confidential", confidentialSecret)), 400, "invalid_grant")
}

func TestPkcePlain(t *testing.T) {
	f := newFixture(t)
	code := f.authorizeCode(t, url.Values{"response_type": {"code"}, "client_id": {"confidential"}, "code_challenge": {codeVerifier}})
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {codeVerifier}}
	expectTokens(t, f.token(form, basic("confidential", confidentialSecret)), true)
}

func TestAuthorizationCodeUserDisabled(t *testing.T) {
	f := newFixture(t)
	code := f.authorizeCode(t, url.Values{"response_type": {"code"}, "client_id": {"confidential"}})
	f.user.Enabled = false
	f.accounts.UpdateUser(context.Background(), f.user)
	expectError(t, f.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}}, basic("confidential", confidentialSecret)), 400, "invalid_grant")
}

// Authorization endpoint validation (RFC 6749 section 3.1 and 4.1.2.1)

func TestAuthorizeErrorsWithoutRedirect(t *testing.T) {
	f := newFixture(t)
	f.interaction.user = f.user
	cases := []url.Values{
		{"response_type": {"code"}},
		{"response_type": {"code"}, "client_id": {"unknown"}},
		{"response_type": {"code"}, "client_id": {"confidential"}, "redirect_uri": {"https://evil.example.com/cb"}},
		{"response_type": {"code"}, "client_id": {"confidential"}, "redirect_uri": {redirectUri, redirectUri}},
		// Multiple registered URIs: the redirect_uri is required
		{"response_type": {"code"}, "client_id": {"public"}, "code_challenge": {codeChallenge}},
	}
	for i, params := range cases {
		f.interaction.err = nil
		r := f.authorize(http.MethodGet, params)
		if r.code == http.StatusFound || f.interaction.err == nil {
			t.Fatalf("case %d: expected an error page, got %d %s", i, r.code, r.header.Get("Location"))
		}
	}
}

func TestAuthorizeErrorsWithRedirect(t *testing.T) {
	f := newFixture(t)
	f.interaction.user = f.user
	cases := []struct {
		params url.Values
		code   string
	}{
		{url.Values{"client_id": {"confidential"}, "state": {"s"}}, "invalid_request"},
		{url.Values{"response_type": {"code", "token"}, "client_id": {"confidential"}, "state": {"s"}}, "invalid_request"},
		{url.Values{"response_type": {"id_token"}, "client_id": {"confidential"}, "state": {"s"}}, "unsupported_response_type"},
		{url.Values{"response_type": {"token"}, "client_id": {"confidential"}, "state": {"s"}}, "unauthorized_client"},
		{url.Values{"response_type": {"code"}, "client_id": {"confidential"}, "scope": {"admin"}, "state": {"s"}}, "invalid_scope"},
	}
	for i, c := range cases {
		u := location(t, f.authorize(http.MethodGet, c.params))
		values := u.Query()
		if c.params.Get("response_type") == "token" {
			values, _ = url.ParseQuery(u.Fragment)
		}
		if values.Get("error") != c.code || values.Get("state") != "s" || values.Get("error_description") == "" {
			t.Fatalf("case %d: expected %s, got %s", i, c.code, u)
		}
	}

	// Inactive user
	f.user.Enabled = false
	f.accounts.UpdateUser(context.Background(), f.user)
	u := location(t, f.authorize(http.MethodGet, url.Values{"response_type": {"code"}, "client_id": {"confidential"}}))
	if u.Query().Get("error") != "access_denied" {
		t.Fatalf("expected access_denied, got %s", u)
	}
}

func TestAuthorizePost(t *testing.T) {
	f := newFixture(t)
	f.interaction.user = f.user
	u := location(t, f.authorize(http.MethodPost, url.Values{"response_type": {"code"}, "client_id": {"confidential"}, "state": {"p"}}))
	if u.Query().Get("code") == "" || u.Query().Get("state") != "p" {
		t.Fatalf("unexpected redirect %s", u)
	}
}

func TestRedirectUriQueryIsRetained(t *testing.T) {
	f := newFixture(t)
	f.interaction.user = f.user
	params := url.Values{
		"response_type": {"code"}, "client_id": {"public"}, "redirect_uri": {"https://client.example.com/other?keep=1"},
		"code_challenge": {codeChallenge}, "code_challenge_method": {"S256"}, "consent": {"allow"},
	}
	u := location(t, f.authorize(http.MethodPost, params))
	if u.Query().Get("keep") != "1" || u.Query().Get("code") == "" {
		t.Fatalf("expected query to be retained, got %s", u)
	}
}

// Implicit grant (RFC 6749 section 4.2)

func TestImplicitGrant(t *testing.T) {
	f := newFixture(t)
	f.interaction.user = f.user
	params := url.Values{"response_type": {"token"}, "client_id": {"public"}, "redirect_uri": {redirectUri}, "state": {"st"}, "consent": {"allow"}}
	u := location(t, f.authorize(http.MethodPost, params))
	if u.RawQuery != "" {
		t.Fatalf("implicit response must use the fragment: %s", u)
	}
	fragment, _ := url.ParseQuery(u.Fragment)
	if fragment.Get("access_token") == "" || fragment.Get("token_type") != "Bearer" || fragment.Get("expires_in") != "3600" ||
		fragment.Get("state") != "st" || fragment.Get("refresh_token") != "" || fragment.Get("scope") != "" {
		t.Fatalf("unexpected fragment %s", u.Fragment)
	}

	// Errors are also sent in the fragment
	params.Set("scope", "admin")
	u = location(t, f.authorize(http.MethodPost, params))
	fragment, _ = url.ParseQuery(u.Fragment)
	if fragment.Get("error") != "invalid_scope" || fragment.Get("state") != "st" {
		t.Fatalf("unexpected fragment %s", u.Fragment)
	}
}

// Refresh token grant (RFC 6749 section 6)

func TestRefreshTokenGrant(t *testing.T) {
	f := newFixture(t)
	auth := basic("confidential", confidentialSecret)
	r := f.token(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct horse"}, "scope": {"api.read api.write"}}, auth)
	refreshToken := r.str("refresh_token")
	firstAccessToken := r.str("access_token")

	// Narrower scope
	r = f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "scope": {"api.read"}}, auth)
	expectTokens(t, r, false) // reuse: the refresh token is not rotated
	if r.str("scope") != "api.read" {
		t.Fatalf("unexpected scope %q", r.str("scope"))
	}
	// The previous access token was replaced
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+firstAccessToken)
	if res := f.do(req); res.code != http.StatusUnauthorized {
		t.Fatalf("expected the previous access token to be revoked, got %d", res.code)
	}

	// Omitted scope: the original scope
	r = f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, auth)
	expectTokens(t, r, false)
	if r.str("scope") != "api.read api.write" {
		t.Fatalf("expected the original scope, got %q", r.str("scope"))
	}

	// Scope escalation
	f.store.UpdateClient(context.Background(), func() *identity.Client {
		c, _ := f.store.GetClientByClientId(context.Background(), "confidential")
		c.AllowedScopes = append(c.AllowedScopes, "admin")
		return c
	}())
	expectError(t, f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "scope": {"api.read admin"}}, auth), 400, "invalid_scope")

	// Another client
	f.addClient(&identity.Client{ClientId: "other", AllowedGrantTypes: []identity.GrantType{identity.GrantTypeRefreshToken}}, "other-secret")
	expectError(t, f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, basic("other", "other-secret")), 400, "invalid_grant")

	// Unknown and expired
	expectError(t, f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"unknown"}}, auth), 400, "invalid_grant")
	f.now = f.now.Add(31 * 24 * time.Hour)
	expectError(t, f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, auth), 400, "invalid_grant")
}

func TestRefreshTokenSlidingExpiration(t *testing.T) {
	f := newFixture(t)
	auth := basic("confidential", confidentialSecret)
	r := f.token(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct horse"}}, auth)
	refreshToken := r.str("refresh_token")
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(20 * 24 * time.Hour)
		expectTokens(t, f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, auth), false)
	}
}

func TestRefreshTokenAbsoluteExpirationSurvivesRotation(t *testing.T) {
	f := newFixture(t)
	client, _ := f.store.GetClientByClientId(context.Background(), "confidential")
	client.RefreshTokenUsage = identity.RefreshTokenUsageOneTime
	client.RefreshTokenExpiration = identity.RefreshTokenExpirationAbsolute
	f.store.UpdateClient(context.Background(), client)
	auth := basic("confidential", confidentialSecret)

	refreshToken := f.token(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct horse"}}, auth).str("refresh_token")
	f.now = f.now.Add(20 * 24 * time.Hour)
	r := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, auth)
	expectTokens(t, r, true)
	f.now = f.now.Add(11 * 24 * time.Hour)
	expectError(t, f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.str("refresh_token")}}, auth), 400, "invalid_grant")
}

func TestNoRefreshTokenWithoutGrant(t *testing.T) {
	f := newFixture(t)
	f.addClient(&identity.Client{ClientId: "norefresh", AllowedGrantTypes: []identity.GrantType{identity.GrantTypePassword}}, "x-secret")
	r := f.token(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct horse"}}, basic("norefresh", "x-secret"))
	expectTokens(t, r, false)
}

// Revocation (RFC 7009) and introspection (RFC 7662)

func TestRevocation(t *testing.T) {
	f := newFixture(t)
	auth := basic("confidential", confidentialSecret)
	r := f.token(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct horse"}}, auth)
	access, refresh := r.str("access_token"), r.str("refresh_token")

	introspect := func(token string) *response {
		return f.post("/introspect", url.Values{"token": {token}}, auth)
	}
	i := introspect(access)
	if i.body["active"] != true || i.str("client_id") != "confidential" || i.str("username") != "alice" || i.str("sub") != f.user.Id ||
		i.str("token_type") != "Bearer" || i.str("scope") != "api.read" || i.str("iss") != "https://id.example.com" {
		t.Fatalf("unexpected introspection %s", i.raw)
	}
	if i := introspect(refresh); i.body["active"] != true || i.str("token_type") != "refresh_token" {
		t.Fatalf("unexpected introspection %s", i.raw)
	}
	if i := introspect("unknown"); i.body["active"] != false || len(i.body) != 1 {
		t.Fatalf("unexpected introspection %s", i.raw)
	}
	// Public clients can't introspect
	expectError(t, f.post("/introspect", url.Values{"token": {access}, "client_id": {"public"}}, ""), 401, "invalid_client")
	expectError(t, f.post("/introspect", url.Values{"token": {access}}, ""), 401, "invalid_client")

	// Another client can't revoke the token
	f.addClient(&identity.Client{ClientId: "other"}, "other-secret")
	if res := f.post("/revoke", url.Values{"token": {refresh}}, basic("other", "other-secret")); res.code != 200 {
		t.Fatalf("expected 200, got %d", res.code)
	}
	if i := introspect(refresh); i.body["active"] != true {
		t.Fatal("token of another client must not be revoked")
	}

	// Revoking the refresh token revokes the access token
	if res := f.post("/revoke", url.Values{"token": {refresh}, "token_type_hint": {"refresh_token"}}, auth); res.code != 200 {
		t.Fatalf("expected 200, got %d", res.code)
	}
	if i := introspect(refresh); i.body["active"] != false {
		t.Fatal("refresh token must be revoked")
	}
	if i := introspect(access); i.body["active"] != false {
		t.Fatal("access token must be revoked")
	}
	// Invalid tokens are accepted
	if res := f.post("/revoke", url.Values{"token": {"unknown"}}, auth); res.code != 200 {
		t.Fatalf("expected 200, got %d", res.code)
	}
	expectError(t, f.post("/revoke", url.Values{}, auth), 400, "invalid_request")
	expectError(t, f.post("/revoke", url.Values{"token": {access}}, ""), 401, "invalid_client")

	// Revoking an access token
	access = f.token(url.Values{"grant_type": {"client_credentials"}}, auth).str("access_token")
	f.post("/revoke", url.Values{"token": {access}}, auth)
	if i := introspect(access); i.body["active"] != false {
		t.Fatal("access token must be revoked")
	}

	// Expired tokens are inactive
	access = f.token(url.Values{"grant_type": {"client_credentials"}}, auth).str("access_token")
	f.now = f.now.Add(2 * time.Hour)
	if i := introspect(access); i.body["active"] != false {
		t.Fatal("expired token must be inactive")
	}
}

// Bearer token usage (RFC 6750)

func TestBearerMiddleware(t *testing.T) {
	f := newFixture(t)
	auth := basic("confidential", confidentialSecret)
	get := func(header string) *response {
		req := httptest.NewRequest(http.MethodGet, "/resource", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		return f.do(req)
	}

	r := get("")
	if r.code != 401 || r.header.Get("WWW-Authenticate") != `Bearer realm="identity"` {
		t.Fatalf("unexpected response %d %v", r.code, r.header)
	}
	r = get("Bearer invalid")
	if r.code != 401 || !strings.Contains(r.header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("unexpected response %d %v", r.code, r.header)
	}
	if r := get("Basic abc"); r.code != 400 {
		t.Fatalf("expected 400, got %d", r.code)
	}

	writeOnly := f.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"api.write"}}, auth).str("access_token")
	r = get("Bearer " + writeOnly)
	if r.code != 403 || !strings.Contains(r.header.Get("WWW-Authenticate"), `error="insufficient_scope"`) || !strings.Contains(r.header.Get("WWW-Authenticate"), `scope="api.read"`) {
		t.Fatalf("unexpected response %d %v", r.code, r.header)
	}

	token := f.token(url.Values{"grant_type": {"client_credentials"}}, auth).str("access_token")
	if r := get("bearer " + token); r.code != 200 {
		t.Fatalf("scheme is case insensitive, got %d", r.code)
	}
	f.now = f.now.Add(time.Hour)
	if r := get("Bearer " + token); r.code != 401 {
		t.Fatalf("expired token must be rejected, got %d", r.code)
	}
}

func TestMetadata(t *testing.T) {
	f := newFixture(t)
	r := f.do(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if r.code != 200 || r.str("issuer") != "https://id.example.com" || r.str("token_endpoint") != "https://id.example.com/token" ||
		r.str("authorization_endpoint") != "https://id.example.com/authorize" {
		t.Fatalf("unexpected metadata %s", r.raw)
	}
}

func TestExtensionGrant(t *testing.T) {
	f := newFixture(t)
	const grantType = "urn:example:params:oauth:grant-type:custom"
	f.server.RegisterGrant(grantType, oauth.GrantHandlerFunc(func(ctx context.Context, req *oauth.TokenRequest) (*oauth.TokenResponse, error) {
		if req.Form.Get("assertion") != "valid" {
			return nil, oauth.NewError(oauth.ErrorInvalidGrant, "bad assertion")
		}
		return f.server.IssueTokens(ctx, req.Client, nil, []string{"api.read"}, oauth.IssueOptions{})
	}))
	f.addClient(&identity.Client{ClientId: "ext", AllowedGrantTypes: []identity.GrantType{grantType}, AllowedScopes: []string{"api.read"}}, "ext-secret")

	expectTokens(t, f.token(url.Values{"grant_type": {grantType}, "assertion": {"valid"}}, basic("ext", "ext-secret")), false)
	expectError(t, f.token(url.Values{"grant_type": {grantType}, "assertion": {"x"}}, basic("ext", "ext-secret")), 400, "invalid_grant")
	expectError(t, f.token(url.Values{"grant_type": {grantType}}, basic("confidential", confidentialSecret)), 400, "unauthorized_client")
}
