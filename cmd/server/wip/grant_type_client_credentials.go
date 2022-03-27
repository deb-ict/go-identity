// Client Credential Grant
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4

package wip

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/response"
)

func ClientCredentialsGrantHandler(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	// Parse the scope
	requestScope := r.FormValue("scope")
	if requestScope == "" {
		//TODO: Get default scope
		requestScope = ""
	}

	// Validate the scopes
	responseScopes := make([]string, 0)
	requestScopes := strings.Split(requestScope, " ")
	if requestScope != "" && len(requestScopes) > 0 {
		for _, scope := range requestScopes {
			if scope == "api.read" || scope == "api.write" {
				fmt.Printf(" - scope: %s\n", scope)
				responseScopes = append(responseScopes, scope)
			} else {
				response.InvalidScope(w)
				return
			}
		}
	}
	responseScope := strings.Join(responseScopes, " ")

	// Setup the claims
	c := identity.Claims{}
	c.SetIssuer("http://localhost:5000")
	c.SetIssuedAt(time.Now())
	c.SetExpiresAt(time.Now().Add(time.Minute * 15))
	//c.SetNotBefore(time.Now().Add(time.Second * 5)) < increase based on request rate
	c.SetAudience("some_audience")
	c.SetScopes(responseScopes...)

	// Generate the token
	token, err := TokenManager.GenerateAccessToken(c)
	if err != nil {
		response.InvalidRequest(w)
		return
	}

	// Return the response
	response := response.TokenResponse{
		AccessToken: token,
		TokenType:   "bearer",
		Expires:     3600,
		Scope:       responseScope,
	}
	response.Write(w)
}
