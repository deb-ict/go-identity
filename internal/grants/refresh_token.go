package grants

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/response"
)

type refreshTokenGrant struct {
	grantTypeBase
}

func NewRefreshTokenGrant() GrantHandler {
	return &refreshTokenGrant{}
}

func (grant *refreshTokenGrant) Handle(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		response.InvalidRequest(w)
		return
	}

	//TODO: Lookup the refresh token
	//		This contains the access token

	// if client.RefreshTokenUsage == OneTimeOnly
	//		Generate a new refresh token
	//		Update the refresh token entry

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
