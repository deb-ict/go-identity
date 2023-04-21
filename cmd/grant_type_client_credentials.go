package main

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
)

func clientCredentialTokenHandler(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	//https://www.rfc-editor.org/rfc/rfc6749#section-4.4
	//		POST /token HTTP/1.1
	//		Host: server.example.com
	//		Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
	//		Content-Type: application/x-www-form-urlencoded
	//		grant_type=client_credentials
	//REQUEST
	//	grant_type				REQUIRED			must be "client_credentials"
	//	scope					OPTIONAL
	//RESPONSE
	//		HTTP/1.1 200 OK
	//		Content-Type: application/json;charset=UTF-8
	//		Cache-Control: no-store
	//		Pragma: no-cache
	//		{json:TokenResponse} (no refresh token)

	//TODO: Parse the scopes
	//TODO: Validate the scopes with the client
	//TODO: Generate the access token
	//TODO: Return access token
}
