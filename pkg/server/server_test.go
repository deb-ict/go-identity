package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deb-ict/go-identity/pkg/account"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/mail"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/server"
	"github.com/deb-ict/go-identity/pkg/store/memory"
)

type env struct {
	t      *testing.T
	srv    *server.Server
	http   *httptest.Server
	mailer *mail.MemorySender
	base   string
}

const (
	basePath     = "/identity"
	adminId      = "admin"
	adminSecret  = "admin-secret"
	appRedirect  = "https://app.example.com/callback"
	codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func newEnv(t *testing.T) *env {
	e := &env{t: t, mailer: &mail.MemorySender{}}
	e.http = httptest.NewUnstartedServer(nil)
	e.base = "http://" + e.http.Listener.Addr().String() + basePath
	var err error
	e.srv, err = server.New(server.Config{
		Store:             memory.New(),
		PublicURL:         e.base,
		ApplicationName:   "Test Identity",
		SessionKey:        bytes.Repeat([]byte("k"), 32),
		Mailer:            e.mailer,
		PasswordHasher:    security.NewBcryptHasher(4),
		AllowRegistration: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.http.Config.Handler = e.srv.Handler()
	e.http.Start()
	t.Cleanup(e.http.Close)

	ctx := context.Background()
	if _, err := e.srv.EnsureClient(ctx, &identity.Client{
		ClientId:          adminId,
		Name:              "Admin",
		Type:              identity.ClientTypeConfidential,
		AllowedGrantTypes: []identity.GrantType{identity.GrantTypeClientCredentials},
		AllowedScopes:     []string{server.DefaultAdminScope, "other"},
		DefaultScopes:     []string{server.DefaultAdminScope},
		Enabled:           true,
	}, adminSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.EnsureClient(ctx, &identity.Client{
		ClientId:          "spa",
		Name:              "Single Page App",
		Type:              identity.ClientTypePublic,
		AllowedGrantTypes: []identity.GrantType{identity.GrantTypeAuthorizationCode, identity.GrantTypeRefreshToken},
		AllowedScopes:     []string{"profile", "api"},
		RedirectUris:      []string{appRedirect},
		RequireConsent:    true,
		Enabled:           true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	return e
}

// browser is an HTTP client with cookies that doesn't follow redirects.
func (e *env) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type result struct {
	status   int
	body     string
	location string
	header   http.Header
}

func (e *env) do(c *http.Client, req *http.Request) *result {
	e.t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &result{status: resp.StatusCode, body: string(body), location: resp.Header.Get("Location"), header: resp.Header}
}

func (e *env) get(c *http.Client, path string) *result {
	e.t.Helper()
	if !strings.HasPrefix(path, "http") {
		path = e.base + path
	}
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	return e.do(c, req)
}

func (e *env) postForm(c *http.Client, path string, form url.Values) *result {
	e.t.Helper()
	if !strings.HasPrefix(path, "http") {
		path = strings.TrimSuffix(e.base, basePath) + path
	}
	req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.do(c, req)
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// form returns the hidden fields of the page.
func form(body string) url.Values {
	values := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(body, -1) {
		values.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return values
}

func expectStatus(t *testing.T, r *result, status int, contains string) {
	t.Helper()
	if r.status != status || !strings.Contains(r.body, contains) {
		t.Fatalf("expected %d containing %q, got %d:\n%s", status, contains, r.status, r.body)
	}
}

func (e *env) linkFromLastMail() string {
	e.t.Helper()
	msg := e.mailer.Last()
	if msg == nil {
		e.t.Fatal("expected an email")
	}
	m := regexp.MustCompile(`https?://\S+token=\S+`).FindString(msg.Text)
	if m == "" {
		e.t.Fatalf("no link in email:\n%s", msg.Text)
	}
	return m
}

func (e *env) login(c *http.Client, login string, password string, returnTo string) *result {
	e.t.Helper()
	page := e.get(c, "/login?"+url.Values{"return_to": {returnTo}}.Encode())
	expectStatus(e.t, page, 200, "Sign in")
	values := form(page.body)
	values.Set("login", login)
	values.Set("password", password)
	return e.postForm(c, basePath+"/login", values)
}

func TestRegistrationActivationLoginAndAuthorizationCodeFlow(t *testing.T) {
	e := newEnv(t)
	b := e.browser()

	// Register
	page := e.get(b, "/register")
	expectStatus(t, page, 200, "Create an account")
	values := form(page.body)
	values.Set("username", "alice")
	values.Set("email", "alice@example.com")
	values.Set("password", "correct horse")
	values.Set("password_confirm", "different")
	expectStatus(t, e.postForm(b, basePath+"/register", values), 400, "The passwords don&#39;t match.")
	values.Set("password_confirm", "correct horse")
	expectStatus(t, e.postForm(b, basePath+"/register", values), 200, "Check your email")
	expectStatus(t, e.postForm(b, basePath+"/register", values), 409, "already in use")

	// Login is refused until the account is activated
	expectStatus(t, e.login(b, "alice", "correct horse", ""), 401, "not activated")

	// Activate with the link from the email
	link := e.linkFromLastMail()
	if !strings.HasPrefix(link, e.base+"/activate?token=") {
		t.Fatalf("unexpected activation link %s", link)
	}
	expectStatus(t, e.get(b, link), 200, "Your account is activated")
	expectStatus(t, e.get(b, link), 400, "invalid or has expired")

	// Start an authorization request (PKCE, public client): redirected to the login page
	authorize := "/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"spa"},
		"redirect_uri":          {appRedirect},
		"scope":                 {"profile api"},
		"state":                 {"state-123"},
		"code_challenge":        {security.S256Challenge(codeVerifier)},
		"code_challenge_method": {"S256"},
	}.Encode()
	r := e.get(b, authorize)
	if r.status != http.StatusSeeOther || !strings.HasPrefix(r.location, basePath+"/login?return_to=") {
		t.Fatalf("expected login redirect, got %d %s", r.status, r.location)
	}
	returnTo, _ := url.Parse(r.location)

	// Login
	expectStatus(t, e.login(b, "alice", "wrong", returnTo.Query().Get("return_to")), 401, "Invalid username or password")
	r = e.login(b, "alice", "correct horse", returnTo.Query().Get("return_to"))
	if r.status != http.StatusSeeOther || !strings.HasPrefix(r.location, basePath+"/authorize?") {
		t.Fatalf("expected redirect back to authorize, got %d %s", r.status, r.location)
	}

	// Consent page
	consent := e.get(b, strings.TrimPrefix(r.location, basePath))
	expectStatus(t, consent, 200, "Single Page App")
	if !strings.Contains(consent.body, "<code>profile</code>") || consent.header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("unexpected consent page:\n%s", consent.body)
	}
	values = form(consent.body)
	values.Set("consent", "allow")

	// Missing CSRF token
	noCsrf := url.Values{}
	for k, v := range values {
		if k != "csrf_token" {
			noCsrf[k] = v
		}
	}
	expectStatus(t, e.postForm(b, basePath+"/authorize", noCsrf), 400, "consent form has expired")

	r = e.postForm(b, basePath+"/authorize", values)
	if r.status != http.StatusFound || !strings.HasPrefix(r.location, appRedirect+"?") {
		t.Fatalf("expected redirect to the client, got %d %s", r.status, r.location)
	}
	callback, _ := url.Parse(r.location)
	if callback.Query().Get("state") != "state-123" {
		t.Fatalf("state mismatch: %s", r.location)
	}

	// Exchange the code
	api := &http.Client{}
	tokens := e.postForm(api, basePath+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {callback.Query().Get("code")},
		"redirect_uri":  {appRedirect},
		"client_id":     {"spa"},
		"code_verifier": {codeVerifier},
	})
	expectStatus(t, tokens, 200, "access_token")
	var tokenResponse map[string]any
	json.Unmarshal([]byte(tokens.body), &tokenResponse)
	if tokenResponse["scope"] != "profile api" || tokenResponse["refresh_token"] == nil {
		t.Fatalf("unexpected token response %s", tokens.body)
	}

	// The user token can't be used on the management API
	req, _ := http.NewRequest(http.MethodGet, e.base+"/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse["access_token"].(string))
	if r := e.do(api, req); r.status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d %s", r.status, r.body)
	}

	// Home page & logout
	expectStatus(t, e.get(b, "/"), 200, "signed in as <strong>alice</strong>")
	logout := e.get(b, "/logout")
	expectStatus(t, logout, 200, "Do you want to sign out")
	expectStatus(t, e.postForm(b, basePath+"/logout", form(logout.body)), 200, "You have been signed out")
	if r := e.get(b, "/"); r.status != http.StatusSeeOther {
		t.Fatalf("expected redirect to login after logout, got %d", r.status)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.srv.Accounts.Register(ctx, "bob", "bob@example.com", "old password")

	// A session in another browser is invalidated by the reset
	other := e.browser()
	e.srv.Accounts.Activate(ctx, strings.SplitN(e.linkFromLastMail(), "token=", 2)[1])
	if r := e.login(other, "bob", "old password", ""); r.status != http.StatusSeeOther {
		t.Fatalf("login failed: %d %s", r.status, r.body)
	}
	expectStatus(t, e.get(other, "/"), 200, "signed in as")

	b := e.browser()
	page := e.get(b, "/password/forgot")
	expectStatus(t, page, 200, "Forgot your password?")
	values := form(page.body)
	values.Set("email", "BOB@example.com")
	expectStatus(t, e.postForm(b, basePath+"/password/forgot", values), 200, "Check your email")

	// Unknown addresses get the same answer, without email
	count := len(e.mailer.Messages())
	values.Set("email", "nobody@example.com")
	expectStatus(t, e.postForm(b, basePath+"/password/forgot", values), 200, "Check your email")
	if len(e.mailer.Messages()) != count {
		t.Fatal("no email expected for unknown addresses")
	}

	link := e.linkFromLastMail()
	if !strings.Contains(link, "/password/reset?token=") {
		t.Fatalf("unexpected reset link %s", link)
	}
	expectStatus(t, e.get(b, "/password/reset?token=invalid"), 400, "invalid or has expired")
	page = e.get(b, link)
	expectStatus(t, page, 200, "Choose a new password")
	if page.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("the reset page must not leak the token through the referrer")
	}
	values = form(page.body)
	values.Set("password", "short")
	values.Set("password_confirm", "short")
	expectStatus(t, e.postForm(b, basePath+"/password/reset", values), 400, "Password is too short.")
	values.Set("password", "new password")
	values.Set("password_confirm", "new password")
	expectStatus(t, e.postForm(b, basePath+"/password/reset", values), 200, "Your password has been changed")
	expectStatus(t, e.postForm(b, basePath+"/password/reset", values), 400, "invalid or has expired")

	if r := e.get(other, "/"); r.status != http.StatusSeeOther {
		t.Fatalf("the old session must be invalid, got %d", r.status)
	}
	expectStatus(t, e.login(b, "bob", "old password", ""), 401, "Invalid username or password")
	if r := e.login(b, "bob", "new password", ""); r.status != http.StatusSeeOther {
		t.Fatalf("login with the new password failed: %d", r.status)
	}
}

func TestResendActivation(t *testing.T) {
	e := newEnv(t)
	e.srv.Accounts.Register(context.Background(), "carol", "carol@example.com", "correct horse")
	b := e.browser()
	page := e.get(b, "/activation/resend")
	values := form(page.body)
	values.Set("email", "carol@example.com")
	count := len(e.mailer.Messages())
	expectStatus(t, e.postForm(b, basePath+"/activation/resend", values), 200, "Check your email")
	if len(e.mailer.Messages()) != count+1 {
		t.Fatal("expected a new activation email")
	}
	expectStatus(t, e.get(b, e.linkFromLastMail()), 200, "Your account is activated")
}

func TestLoginSecurity(t *testing.T) {
	e := newEnv(t)
	e.srv.Accounts.CreateUser(context.Background(), accountInput("dave"))
	b := e.browser()

	// CSRF
	expectStatus(t, e.postForm(b, basePath+"/login", url.Values{"login": {"dave"}, "password": {"correct horse"}}), 400, "Your form has expired")

	// Open redirects are not followed
	for _, target := range []string{"//evil.example.com", "https://evil.example.com", "/\\evil.example.com"} {
		c := e.browser()
		r := e.login(c, "dave", "correct horse", target)
		if r.status != http.StatusSeeOther || r.location != basePath+"/" {
			t.Fatalf("return_to %q: expected redirect home, got %d %s", target, r.status, r.location)
		}
	}

	// Cookies are scoped to the base path and HttpOnly
	c := e.browser()
	page := e.get(c, "/login")
	cookie := page.header.Get("Set-Cookie")
	if !strings.Contains(cookie, "Path=/identity") || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Lax") {
		t.Fatalf("unexpected cookie %s", cookie)
	}
}

func accountInput(username string) account.CreateUserInput {
	return account.CreateUserInput{
		Username:      username,
		Email:         username + "@example.com",
		Password:      "correct horse",
		EmailVerified: true,
		Enabled:       true,
	}
}

// Management API

type apiClient struct {
	e     *env
	token string
}

func (e *env) admin() *apiClient {
	r := e.postForm(&http.Client{}, basePath+"/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {adminId}, "client_secret": {adminSecret},
	})
	expectStatus(e.t, r, 200, "access_token")
	var body map[string]any
	json.Unmarshal([]byte(r.body), &body)
	return &apiClient{e: e, token: body["access_token"].(string)}
}

func (a *apiClient) call(method string, path string, body any, out any) int {
	a.e.t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, a.e.base+"/api"+path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	r := a.e.do(&http.Client{}, req)
	if out != nil && r.body != "" {
		if err := json.Unmarshal([]byte(r.body), out); err != nil {
			a.e.t.Fatalf("invalid json %s: %v", r.body, err)
		}
	}
	return r.status
}

func TestAPIAuthorization(t *testing.T) {
	e := newEnv(t)
	anonymous := &apiClient{e: e}
	if status := anonymous.call(http.MethodGet, "/clients", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
	invalid := &apiClient{e: e, token: "invalid"}
	if status := invalid.call(http.MethodGet, "/clients", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}

	r := e.postForm(&http.Client{}, basePath+"/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {adminId}, "client_secret": {adminSecret}, "scope": {"other"},
	})
	var body map[string]any
	json.Unmarshal([]byte(r.body), &body)
	wrongScope := &apiClient{e: e, token: body["access_token"].(string)}
	if status := wrongScope.call(http.MethodGet, "/clients", nil, nil); status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", status)
	}
}

func TestAPIClients(t *testing.T) {
	e := newEnv(t)
	a := e.admin()

	var list map[string]any
	if status := a.call(http.MethodGet, "/clients?limit=1", nil, &list); status != 200 || list["total"] != float64(2) || len(list["items"].([]any)) != 1 {
		t.Fatalf("unexpected list %d %v", status, list)
	}

	// Validation
	var apiErr map[string]any
	if status := a.call(http.MethodPost, "/clients", map[string]any{"client_id": "x", "redirect_uris": []string{"relative"}}, &apiErr); status != 400 || apiErr["field"] != "redirect_uris" {
		t.Fatalf("expected validation error, got %d %v", status, apiErr)
	}
	if status := a.call(http.MethodPost, "/clients", map[string]any{"client_id": "x", "unknown": 1}, nil); status != 400 {
		t.Fatalf("expected 400 for unknown fields, got %d", status)
	}
	if status := a.call(http.MethodPost, "/clients", map[string]any{"client_id": "spa"}, nil); status != 409 {
		t.Fatalf("expected 409 for duplicate client id, got %d", status)
	}

	// Create a confidential client: the secret is returned once
	var created map[string]any
	status := a.call(http.MethodPost, "/clients", map[string]any{
		"client_id":      "backend",
		"name":           "Backend",
		"grant_types":    []string{"client_credentials"},
		"allowed_scopes": []string{"api"},
	}, &created)
	if status != 201 || created["client_secret"] == "" || created["has_secret"] != true || created["enabled"] != true ||
		created["access_token_lifetime"] != float64(3600) || created["refresh_token_usage"] != "reuse" {
		t.Fatalf("unexpected create response %d %v", status, created)
	}
	id := created["id"].(string)
	secret := created["client_secret"].(string)

	token := func(secret string) int {
		return e.postForm(&http.Client{}, basePath+"/token", url.Values{
			"grant_type": {"client_credentials"}, "client_id": {"backend"}, "client_secret": {secret},
		}).status
	}
	if token(secret) != 200 {
		t.Fatal("expected the new client to get a token")
	}

	var got map[string]any
	if status := a.call(http.MethodGet, "/clients/"+id, nil, &got); status != 200 || got["client_id"] != "backend" || got["client_secret"] != nil {
		t.Fatalf("unexpected get response %d %v", status, got)
	}
	if status := a.call(http.MethodGet, "/clients/unknown", nil, nil); status != 404 {
		t.Fatalf("expected 404, got %d", status)
	}

	// Tokens of the client are listed and revoked when the client is disabled
	var tokens map[string]any
	a.call(http.MethodGet, "/tokens?client_id="+id, nil, &tokens)
	if tokens["total"] != float64(1) {
		t.Fatalf("expected 1 token, got %v", tokens)
	}
	var updated map[string]any
	status = a.call(http.MethodPut, "/clients/"+id, map[string]any{
		"client_id": "backend", "name": "Backend v2", "grant_types": []string{"client_credentials"},
		"allowed_scopes": []string{"api"}, "enabled": false, "access_token_lifetime": 60,
	}, &updated)
	if status != 200 || updated["name"] != "Backend v2" || updated["enabled"] != false || updated["access_token_lifetime"] != float64(60) {
		t.Fatalf("unexpected update response %d %v", status, updated)
	}
	a.call(http.MethodGet, "/tokens?client_id="+id, nil, &tokens)
	if tokens["total"] != float64(0) {
		t.Fatalf("expected tokens to be revoked, got %v", tokens)
	}
	if token(secret) != 401 {
		t.Fatal("disabled client must not get a token")
	}

	// Regenerate the secret
	a.call(http.MethodPut, "/clients/"+id, map[string]any{"client_id": "backend", "grant_types": []string{"client_credentials"}, "enabled": true}, nil)
	var secretResponse map[string]any
	if status := a.call(http.MethodPost, "/clients/"+id+"/secret", nil, &secretResponse); status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if token(secret) != 401 || token(secretResponse["client_secret"].(string)) != 200 {
		t.Fatal("expected only the new secret to work")
	}

	// Delete
	if status := a.call(http.MethodDelete, "/clients/"+id, nil, nil); status != 204 {
		t.Fatalf("expected 204, got %d", status)
	}
	if status := a.call(http.MethodDelete, "/clients/"+id, nil, nil); status != 404 {
		t.Fatalf("expected 404, got %d", status)
	}
}

func TestAPIUsersAndTokens(t *testing.T) {
	e := newEnv(t)
	a := e.admin()

	var user map[string]any
	status := a.call(http.MethodPost, "/users", map[string]any{
		"username": "erin", "email": "erin@example.com", "send_activation": true,
	}, &user)
	if status != 201 || user["email_verified"] != false || user["has_password"] != false || user["password_hash"] != nil {
		t.Fatalf("unexpected create response %d %v", status, user)
	}
	id := user["id"].(string)
	if msg := e.mailer.Last(); msg == nil || msg.To != "erin@example.com" {
		t.Fatal("expected an activation email")
	}
	if status := a.call(http.MethodPost, "/users", map[string]any{"username": "ERIN", "email": "other@example.com"}, nil); status != 409 {
		t.Fatalf("expected 409, got %d", status)
	}
	var apiErr map[string]any
	if status := a.call(http.MethodPost, "/users", map[string]any{"username": "x", "email": "x@example.com"}, &apiErr); status != 400 || apiErr["field"] != "username" {
		t.Fatalf("expected validation error, got %d %v", status, apiErr)
	}

	// Set the password and verify the email
	if status := a.call(http.MethodPost, "/users/"+id+"/password", map[string]any{"password": "short"}, nil); status != 400 {
		t.Fatalf("expected 400, got %d", status)
	}
	if status := a.call(http.MethodPost, "/users/"+id+"/password", map[string]any{"password": "correct horse"}, nil); status != 204 {
		t.Fatalf("expected 204, got %d", status)
	}
	if status := a.call(http.MethodPost, "/users/"+id+"/activation", nil, nil); status != 202 {
		t.Fatalf("expected 202, got %d", status)
	}
	status = a.call(http.MethodPut, "/users/"+id, map[string]any{"username": "erin", "email": "erin@example.com", "email_verified": true, "enabled": true}, &user)
	if status != 200 || user["email_verified"] != true || user["has_password"] != true {
		t.Fatalf("unexpected update response %d %v", status, user)
	}
	if status := a.call(http.MethodPost, "/users/"+id+"/activation", nil, nil); status != 409 {
		t.Fatalf("expected 409 for a verified user, got %d", status)
	}

	// Search
	var list map[string]any
	a.call(http.MethodGet, "/users?search=ERI", nil, &list)
	if list["total"] != float64(1) {
		t.Fatalf("unexpected search result %v", list)
	}

	// Lock the account with failed logins, then unlock it
	b := e.browser()
	for i := 0; i < 5; i++ {
		e.login(b, "erin", "wrong", "")
	}
	a.call(http.MethodGet, "/users/"+id, nil, &user)
	if user["locked_out"] != true {
		t.Fatalf("expected the user to be locked out: %v", user)
	}
	a.call(http.MethodPost, "/users/"+id+"/unlock", nil, &user)
	if user["locked_out"] != false {
		t.Fatalf("expected the user to be unlocked: %v", user)
	}
	if r := e.login(b, "erin", "correct horse", ""); r.status != http.StatusSeeOther {
		t.Fatalf("login failed after unlock: %d", r.status)
	}

	// Issue tokens for the user and manage them
	e.srv.EnsureClient(context.Background(), &identity.Client{
		ClientId: "cli", Type: identity.ClientTypeConfidential, Enabled: true,
		AllowedGrantTypes: []identity.GrantType{identity.GrantTypePassword, identity.GrantTypeRefreshToken},
	}, "cli-secret")
	for i := 0; i < 2; i++ {
		r := e.postForm(&http.Client{}, basePath+"/token", url.Values{
			"grant_type": {"password"}, "username": {"erin"}, "password": {"correct horse"}, "client_id": {"cli"}, "client_secret": {"cli-secret"},
		})
		expectStatus(t, r, 200, "refresh_token")
	}
	var tokens map[string]any
	a.call(http.MethodGet, "/tokens?user_id="+id, nil, &tokens)
	if tokens["total"] != float64(2) {
		t.Fatalf("expected 2 access tokens, got %v", tokens)
	}
	first := tokens["items"].([]any)[0].(map[string]any)
	if first["user_id"] != id || first["expired"] != false {
		t.Fatalf("unexpected token %v", first)
	}
	var one map[string]any
	if status := a.call(http.MethodGet, "/tokens/"+first["id"].(string), nil, &one); status != 200 || one["id"] != first["id"] {
		t.Fatalf("unexpected token %d %v", status, one)
	}
	if status := a.call(http.MethodDelete, "/tokens/"+first["id"].(string), nil, nil); status != 204 {
		t.Fatalf("expected 204, got %d", status)
	}
	var refreshTokens map[string]any
	a.call(http.MethodGet, "/refresh-tokens?user_id="+id, nil, &refreshTokens)
	if refreshTokens["total"] != float64(2) {
		t.Fatalf("expected 2 refresh tokens, got %v", refreshTokens)
	}
	refreshId := refreshTokens["items"].([]any)[0].(map[string]any)["id"].(string)
	if status := a.call(http.MethodDelete, "/refresh-tokens/"+refreshId, nil, nil); status != 204 {
		t.Fatalf("expected 204, got %d", status)
	}
	if status := a.call(http.MethodDelete, "/tokens", nil, nil); status != 400 {
		t.Fatalf("bulk delete without a filter must be refused, got %d", status)
	}
	var revoked map[string]any
	a.call(http.MethodDelete, "/users/"+id+"/tokens", nil, &revoked)
	if revoked["refresh_tokens"] != float64(1) {
		t.Fatalf("unexpected revoke response %v", revoked)
	}

	// Password reset email
	if status := a.call(http.MethodPost, "/users/"+id+"/password-reset", nil, nil); status != 202 {
		t.Fatalf("expected 202, got %d", status)
	}
	if !strings.Contains(e.mailer.Last().Subject, "reset your password") {
		t.Fatal("expected a password reset email")
	}

	// Delete
	if status := a.call(http.MethodDelete, "/users/"+id, nil, nil); status != 204 {
		t.Fatalf("expected 204, got %d", status)
	}
	if status := a.call(http.MethodGet, "/users/"+id, nil, nil); status != 404 {
		t.Fatalf("expected 404, got %d", status)
	}
}

func TestMetadataAndCleanup(t *testing.T) {
	e := newEnv(t)
	r := e.get(e.browser(), "/.well-known/oauth-authorization-server")
	expectStatus(t, r, 200, `"issuer":"`+e.base+`"`)
	if !strings.Contains(r.body, `"authorization_endpoint":"`+e.base+`/authorize"`) {
		t.Fatalf("unexpected metadata %s", r.body)
	}
	if err := e.srv.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.srv.RunCleanup(ctx, time.Millisecond)
		close(done)
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
}

func TestConfigValidation(t *testing.T) {
	if _, err := server.New(server.Config{}); err == nil {
		t.Fatal("expected an error without store")
	}
	if _, err := server.New(server.Config{Store: memory.New(), PublicURL: "/relative"}); err == nil {
		t.Fatal("expected an error for a relative public url")
	}
	if _, err := server.New(server.Config{Store: memory.New(), PublicURL: "https://id.example.com", SessionKey: []byte("short")}); err == nil {
		t.Fatal("expected an error for a short session key")
	}
}
