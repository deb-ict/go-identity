package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-router"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	//example parameter
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
	HelpUri     string `json:"error_uri,omitempty"`
}

func (t *TokenResponse) Send(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(t)
}

func (e *ErrorResponse) Send(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)
	return json.NewEncoder(w).Encode(e)
}

func authorizeHandlerError(w http.ResponseWriter, e string) {

}

func tokenHandlerError(w http.ResponseWriter, e string) {

}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// Validate the method
	if r.Method != http.MethodGet {
		authorizeHandlerError(w, "invalid_request")
		return
	}

	// Validate the content type
	headerContentType := r.Header.Get("Content-Type")
	if headerContentType != "application/x-www-form-urlencoded" {
		authorizeHandlerError(w, "invalid_request")
		return
	}

	// Parse the form
	if r.Form == nil {
		r.ParseForm()
	}

	// Get the client
	clientId, clientSecret, useBasicAuth := r.BasicAuth()
	if !useBasicAuth {
		clientIdParam := r.Form["client_id"]
		if len(clientIdParam) != 1 {
			authorizeHandlerError(w, "invalid_request")
			return
		}
		clientId = clientIdParam[0]

		clientSecretParam := r.Form["client_secret"]
		if len(clientSecretParam) > 1 {
			authorizeHandlerError(w, "invalid_request")
			return
		}
		clientSecret = clientSecretParam[0]
	}
	if clientId != "my_client" || clientSecret != "my_secret" {
		authorizeHandlerError(w, "unauthorized_client")
		return
	}
	client := &identity.Client{
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}

	responseType := r.Form["response_type"]
	if len(responseType) != 1 {
		authorizeHandlerError(w, "invalid_request")
		return
	}

	state := r.Form["state"]
	if len(state) != 1 {
		authorizeHandlerError(w, "invalid_request")
		return
	}

	scope := r.Form["scope"]
	if len(scope) > 1 {
		authorizeHandlerError(w, "invalid_request")
		return
	}

	redirectUri := r.Form["redirect_uri"]
	if len(redirectUri) > 1 {
		authorizeHandlerError(w, "invalid_request")
		return
	}

	requestedScopes := strings.Split(scope[0], " ")
	if !client.ValidateScopes(requestedScopes) {
		authorizeHandlerError(w, "invalid_scope")
		return
	}

	// Get the response type
	switch responseType[0] {
	case "code":
		codeAuthorizeHandler(w, r, client, state[0], redirectUri[0], strings.Split(scope[0], " "))
	case "token":
		tokenAuthorizeHandler(w, r, client, state[0], redirectUri[0], strings.Split(scope[0], " "))
	default:
		authorizeHandlerError(w, "unsupported_response_type")
	}
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	// Validate the method
	if r.Method != http.MethodPost {
		tokenHandlerError(w, "invalid_request")
		return
	}

	// Validate the content type
	headerContentType := r.Header.Get("Content-Type")
	if headerContentType != "application/x-www-form-urlencoded" {
		tokenHandlerError(w, "invalid_request")
		return
	}

	// Parse the form
	if r.Form == nil {
		r.ParseForm()
	}

	// Get the client
	clientId, clientSecret, useBasicAuth := r.BasicAuth()
	if !useBasicAuth {
		clientIdParam := r.Form["client_id"]
		if len(clientIdParam) != 1 {
			tokenHandlerError(w, "invalid_request")
			return
		}
		clientId = clientIdParam[0]

		clientSecretParam := r.Form["client_secret"]
		if len(clientSecretParam) > 1 {
			tokenHandlerError(w, "invalid_request")
			return
		}
		clientSecret = clientSecretParam[0]
	}
	if clientId != "my_client" || clientSecret != "my_secret" {
		tokenHandlerError(w, "unauthorized_client")
		return
	}
	client := &identity.Client{
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}

	grantType := r.Form["grant_type"]
	if len(grantType) != 1 {
		tokenHandlerError(w, "invalid_request")
		return
	}

	switch grantType[0] {
	case "authorization_code":
		authorizationCodeTokenHandler(w, r, client)
	case "client_credentials":
		clientCredentialTokenHandler(w, r, client)
	case "password":
		passwordTokenHandler(w, r, client)
	case "refresh_token":
		refreshTokenTokenHandler(w, r, client)
	default:
		tokenHandlerError(w, "unsupported_grant_type")
	}
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello identity!")
}

func main() {
	router := router.NewRouter()
	router.HandleFunc("/", helloHandler)
	router.HandleFunc("/authorize", authorizeHandler)
	router.HandleFunc("/token", tokenHandler)

	log.Fatal(http.ListenAndServe("127.0.0.1:8050", router))
}
