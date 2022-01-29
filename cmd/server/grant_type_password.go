// Resource Owner Password Credential Grany
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3

package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/deb-ict/go-identity/pkg/response"
)

func PasswordGrantHandler(w http.ResponseWriter, r *http.Request, client *Client) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		response.InvalidRequest(w)
		return
	}

	if username != "myuser" || password != "mypass" {
		response.InvalidRequest(w) //TODO: Set correct error
		return
	}

	//OPTIONAL: scope
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
