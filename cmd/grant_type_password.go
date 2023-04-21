package main

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
)

func passwordTokenHandler(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	//https://www.rfc-editor.org/rfc/rfc6749#section-4.3
	//		POST /token HTTP/1.1
	//		Host: server.example.com
	//		Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
	//		Content-Type: application/x-www-form-urlencoded
	//		grant_type=password&username=johndoe&password=A3ddj3w
	//REQUEST
	//	grant_type				REQUIRED			must be "password"
	//	username				REQUIRED
	//	password				REQUIRED
	//	scope					OPTIONAL
	//RESPONSE
	//		HTTP/1.1 200 OK
	//		Content-Type: application/json;charset=UTF-8
	//		Cache-Control: no-store
	//		Pragma: no-cache
	//		{json:TokenResponse}

	//TODO: Parse the scopes
	//TODO: Validate the scopes with the client
	//TODO: Parse user credentials
	//TODO: Get the user by username
	//TODO: Validate user password
	//TODO: Generate the access token
	//TODO: Return access token
}
