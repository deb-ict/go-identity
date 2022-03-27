//
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1

package wip

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/response"
)

func AuthorizationCodeGrantHandler(w http.ResponseWriter, r *http.Request, client *identity.Client) {
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

	response := response.TokenResponse{
		AccessToken:  "this_is_my_secret_token",
		RefreshToken: "refresh_with_me",
		TokenType:    "bearer",
		Expires:      3600,
		Scope:        "api.read",
	}
	response.Write(w)
}
