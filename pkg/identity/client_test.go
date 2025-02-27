package identity

import (
	"testing"
	"time"
)

func Test_Client_EnsureDefaults(t *testing.T) {
	client := &Client{}
	client.EnsureDefaults()

	expectedAccessTokenLifetime := 3600 * time.Second
	expectedAuthorizationCodeLifetime := 300 * time.Second
	expectedRefreshTokenLifetime := 720 * time.Hour

	if client.RefreshTokenUsage != RefreshTokenUsageReUse {
		t.Errorf("Incorrect default Refresh token usage: got %v, expected %v", client.RefreshTokenUsage, RefreshTokenUsageReUse)
	}
	if client.RefreshTokenExpiration != RefreshTokenExpirationSliding {
		t.Errorf("Incorrect default Refresh token expiration: got %v, expected %v", client.RefreshTokenExpiration, RefreshTokenExpirationSliding)
	}
	if client.AccessTokenLifetime != expectedAccessTokenLifetime {
		t.Errorf("Incorrect default access token lifetime: got %v, expected %v", client.AccessTokenLifetime, expectedAccessTokenLifetime)
	}
	if client.AuthorizationCodeLifetime != expectedAuthorizationCodeLifetime {
		t.Errorf("Incorrect default authorization code lifetime: got %v, expected %v", client.AuthorizationCodeLifetime, expectedAuthorizationCodeLifetime)
	}
	if client.RefreshTokenLifetime != expectedRefreshTokenLifetime {
		t.Errorf("Incorrect default refresh token lifetime: got %v, expected %v", client.RefreshTokenLifetime, expectedRefreshTokenLifetime)
	}
}

func Test_Client_AccessTokenLifetimeSeconds(t *testing.T) {
	client := &Client{
		AccessTokenLifetime: 300 * time.Second,
	}

	expected := 300
	value := client.AccessTokenLifetimeSeconds()
	if value != expected {
		t.Errorf("Incorrect access token lifetime in seconds: got %v, expected %v", value, expected)
	}
}

func Test_Client_AuthorizationCodeLifetimeSeconds(t *testing.T) {
	client := &Client{
		AuthorizationCodeLifetime: 300 * time.Second,
	}

	expected := 300
	value := client.AuthorizationCodeLifetimeSeconds()
	if value != expected {
		t.Errorf("Incorrect authorization token lifetime in seconds: got %v, expected %v", value, expected)
	}
}

func Test_Client_RefreshTokenLifetimeSeconds(t *testing.T) {
	client := &Client{
		RefreshTokenLifetime: 300 * time.Second,
	}

	expected := 300
	value := client.RefreshTokenLifetimeSeconds()
	if value != expected {
		t.Errorf("Incorrect refresh token lifetime in seconds: got %v, expected %v", value, expected)
	}
}

func Test_Client_ValidateRedirectUri(t *testing.T) {
	client := &Client{
		RedirectUris: []string{
			"http://localhost",
			"http://localhost:5060",
			"https://www.cloudbm.eu/auth/callback",
		},
	}

	type Test struct {
		RedirectUri string
		Expected    bool
	}
	tests := []Test{
		{"http://localhost", true},
		{"https://www.cloudbm.eu/auth/callback", true},
		{"https://example.com", false},
	}

	for _, test := range tests {
		result := client.ValidateRedirectUri(test.RedirectUri)
		if result != test.Expected {
			t.Errorf("Failed to validate redirect uri: got %v, expected %v", test.Expected, result)
		}
	}
}

func Test_Client_ValidateGrantType(t *testing.T) {
	client := &Client{
		AllowedGrantTypes: []GrantType{
			GrantTypeAuthorizationCode,
			GrantTypeClientCredentials,
		},
	}

	type Test struct {
		GrantType GrantType
		Expected  bool
	}
	tests := []Test{
		{GrantTypeAuthorizationCode, true},
		{GrantTypeClientCredentials, true},
		{GrantTypeRefreshToken, false},
	}

	for _, test := range tests {
		result := client.ValidateGrantType(test.GrantType)
		if result != test.Expected {
			t.Errorf("Failed to validate grant type: got %v, expected %v", test.Expected, result)
		}
	}
}

func Test_Client_ValidateScope(t *testing.T) {
	client := &Client{
		AllowedScopes: []string{
			"api.read",
			"api.write",
		},
	}

	type Test struct {
		Scope    string
		Expected bool
	}
	tests := []Test{
		{"api.read", true},
		{"api.write", true},
		{"api.delete", false},
	}

	for _, test := range tests {
		result := client.ValidateScope(test.Scope)
		if result != test.Expected {
			t.Errorf("Failed to validate scope: got %v, expected %v", test.Expected, result)
		}
	}
}

func Test_Client_ValidateScopes(t *testing.T) {
	client := &Client{
		AllowedScopes: []string{
			"api.read",
			"api.write",
		},
	}

	type Test struct {
		Scopes   []string
		Expected bool
	}
	tests := []Test{
		{[]string{"api.read"}, true},
		{[]string{"api.write"}, true},
		{[]string{"api.read", "api.write"}, true},
		{[]string{"api.delete"}, false},
		{[]string{"api.read", "api.write", "api.delete"}, false},
	}

	for _, test := range tests {
		result := client.ValidateScopes(test.Scopes)
		if result != test.Expected {
			t.Errorf("Failed to validate scope: got %v, expected %v", test.Expected, result)
		}
	}
}
