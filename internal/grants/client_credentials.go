package grants

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/response"
)

type clientCredentialsGrant struct {
	grantTypeBase
}

func NewClientCredentialsGrant() GrantHandler {
	return &clientCredentialsGrant{}
}

func (grant *clientCredentialsGrant) Handle(w http.ResponseWriter, r *http.Request, client *identity.Client) {

	access_token := "my_access_token"
	available_scopes := "my_scope"

	// Return the response
	response := response.TokenResponse{
		AccessToken: access_token,
		TokenType:   "bearer",
		Expires:     3600,
		Scope:       available_scopes,
	}
	response.Write(w)
}
