package grants

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/response"
)

type authorizationCodeGrant struct {
	grantTypeBase
}

func NewAuthorizationCodeGrant() GrantHandler {
	return &authorizationCodeGrant{}
}

func (grant *authorizationCodeGrant) Handle(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	//code := r.FormValue("code")
	//redirect_uri := r.FormValue("redirect_uri")

	//Lookup authorization_code
	//	authCode, err := authCodeStore.Get(client.ClientId, code)
	//Validate
	//	authCode.redirect_uri = redirect_uri
	//Validate
	//	expiration

	//TODO: Login the user

	//TODO: Delete authCode

	//Access token response

	access_token := "my_access_token"
	refresh_token := "my_refresh_token"
	available_scopes := "my_scope"

	response := response.TokenResponse{
		AccessToken:  access_token,
		RefreshToken: refresh_token,
		TokenType:    "bearer",
		Expires:      3600,
		Scope:        available_scopes,
	}
	response.Write(w)
}
