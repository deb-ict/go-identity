// Refresh access token
// https://datatracker.ietf.org/doc/html/rfc6749#section-6

package wip

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/response"
)

func RefreshTokenGrantHandler(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		response.InvalidRequest(w)
		return
	}

	//TODO: Scopes (optional)
	//	Can be less, but not more as original request
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

	response := response.TokenResponse{
		AccessToken:  "this_is_my_secret_token",
		RefreshToken: "refresh_with_me",
		TokenType:    "bearer",
		Expires:      3600,
		Scope:        responseScope,
	}
	response.Write(w)
}
