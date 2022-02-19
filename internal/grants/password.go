package grants

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/response"
)

type passwordGrant struct {
	grantTypeBase
}

func NewPasswordGrant() GrantHandler {
	return &passwordGrant{}
}

func (grant *passwordGrant) Handle(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	// Make sure username & password are present
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		response.InvalidRequest(w)
		return
	}

	access_token := "my_access_token"
	refresh_token := "my_refresh_token"
	available_scopes := "my_scope"

	// Return the response
	response := response.TokenResponse{
		AccessToken:  access_token,
		RefreshToken: refresh_token,
		TokenType:    "bearer",
		Expires:      3600,
		Scope:        available_scopes,
	}
	response.Write(w)
}
