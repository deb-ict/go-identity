package wip

import (
	"net/http"

	"github.com/deb-ict/go-identity/internal/grants"
	"github.com/deb-ict/go-identity/pkg/response"
)

// OAuth 2.0 Token Endpoint
// https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
//	Content-Type: application/x-www-form-urlencoded
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	// Parse the form
	err = r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Get the grant type
	var grantHandler grants.GrantTypeHandler
	grant_type := r.FormValue("grant_type")
	if grant_type == "" {
		response.InvalidRequest(w)
		return
	}

	switch grant_type {
	case "authorization_code":
		grantHandler = AuthorizationCodeGrantHandler
	case "client_credentials":
		grantHandler = ClientCredentialsGrantHandler
	case "password":
		grantHandler = PasswordGrantHandler
	case "refresh_token":
		grantHandler = RefreshTokenGrantHandler
	default:
		response.InvalidGrant(w)
		return
	}

	client, err := ClientManager.GetClientFromRequest(w, r)
	if err != nil {
		return
	}

	// Process grant
	grantHandler(w, r, client)
}
