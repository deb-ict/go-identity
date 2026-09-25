package identity

import (
	"reflect"
	"testing"
	"time"
)

func TestParseScope(t *testing.T) {
	cases := map[string][]string{
		"":                   {},
		"a":                  {"a"},
		"a b":                {"a", "b"},
		"  a   b a ":         {"a", "b"},
		"api.read api.write": {"api.read", "api.write"},
	}
	for input, expected := range cases {
		if got := ParseScope(input); !reflect.DeepEqual(got, expected) {
			t.Errorf("ParseScope(%q) = %v, expected %v", input, got, expected)
		}
	}
	if FormatScope([]string{"a", "b"}) != "a b" {
		t.Fatal("unexpected format")
	}
}

func TestScopeTokenSyntax(t *testing.T) {
	for _, valid := range []string{"a", "api.read", "https://api.example.com/read", "!#[]~"} {
		if !IsValidScopeToken(valid) {
			t.Errorf("expected %q to be valid", valid)
		}
	}
	for _, invalid := range []string{"", "a b", `a"b`, `a\b`, "é", "a\tb"} {
		if IsValidScopeToken(invalid) {
			t.Errorf("expected %q to be invalid", invalid)
		}
	}
}

func TestClientValidate(t *testing.T) {
	valid := func() *Client {
		c := &Client{
			ClientId:          "client",
			RedirectUris:      []string{"https://example.com/cb?x=1", "com.example.app:/oauth"},
			AllowedScopes:     []string{"a", "b"},
			DefaultScopes:     []string{"a"},
			AllowedGrantTypes: []GrantType{GrantTypeAuthorizationCode, GrantTypeClientCredentials},
		}
		c.EnsureDefaults()
		return c
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("expected valid client: %v", err)
	}
	cases := map[string]func(c *Client){
		"client_id":                func(c *Client) { c.ClientId = "" },
		"type":                     func(c *Client) { c.Type = "other" },
		"redirect_uris":            func(c *Client) { c.RedirectUris = []string{"/relative"} },
		"redirect fragment":        func(c *Client) { c.RedirectUris = []string{"https://example.com/cb#frag"} },
		"scope syntax":             func(c *Client) { c.AllowedScopes = []string{"a b"} },
		"default scopes":           func(c *Client) { c.DefaultScopes = []string{"c"} },
		"public client_credential": func(c *Client) { c.Type = ClientTypePublic },
		"refresh usage":            func(c *Client) { c.RefreshTokenUsage = "x" },
		"refresh expiration":       func(c *Client) { c.RefreshTokenExpiration = "x" },
	}
	for name, mutate := range cases {
		c := valid()
		mutate(c)
		if err := c.Validate(); !IsValidationError(err) {
			t.Errorf("%s: expected validation error, got %v", name, err)
		}
	}
}

func TestClientDefaults(t *testing.T) {
	c := &Client{}
	c.EnsureDefaults()
	if c.Type != ClientTypeConfidential || c.AccessTokenLifetime != time.Hour || c.AuthorizationCodeLifetime != 5*time.Minute ||
		c.RefreshTokenUsage != RefreshTokenUsageReUse || c.RefreshTokenExpiration != RefreshTokenExpirationSliding {
		t.Fatalf("unexpected defaults %+v", c)
	}
}

func TestUserValidate(t *testing.T) {
	u := &User{Username: " Alice ", Email: " Alice@Example.COM "}
	u.Normalize()
	if u.Username != "Alice" || u.NormalizedUsername != "alice" || u.NormalizedEmail != "alice@example.com" {
		t.Fatalf("unexpected normalization %+v", u)
	}
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ab", "has space", "semi;colon"} {
		if ValidateUsername(name) == nil {
			t.Errorf("expected %q to be invalid", name)
		}
	}
	for _, email := range []string{"", "no-at", "Name <a@example.com>"} {
		if ValidateEmail(email) == nil {
			t.Errorf("expected %q to be invalid", email)
		}
	}
}

func TestExpiration(t *testing.T) {
	now := time.Now()
	token := &RefreshToken{TokenExpiration: RefreshTokenExpirationSliding, Lifetime: time.Hour, ExpiresAt: now.Add(time.Minute)}
	token.Touch(now)
	if !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatal("sliding expiration must restart")
	}
	token = &RefreshToken{TokenExpiration: RefreshTokenExpirationAbsolute, Lifetime: time.Hour, ExpiresAt: now.Add(time.Minute)}
	token.Touch(now)
	if !token.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("absolute expiration must not change")
	}
	if !token.HasExpired(now.Add(time.Minute)) || token.HasExpired(now) {
		t.Fatal("unexpected expiration")
	}
}
