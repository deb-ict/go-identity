package main

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
)

func refreshTokenTokenHandler(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	//https://www.rfc-editor.org/rfc/rfc6749#section-6
	//		POST /token HTTP/1.1
	//		Host: server.example.com
	//		Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
	//		Content-Type: application/x-www-form-urlencoded
	//		grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
	//REQUEST
	//	grant_type				REQUIRED			must be "refresh_token"
	//	refresh_token			REQUIRED
	//	scope					OPTIONAL			!should not include more as original request
	//RESPONSE
	//		HTTP/1.1 200 OK
	//		Content-Type: application/json;charset=UTF-8
	//		Cache-Control: no-store
	//		Pragma: no-cache
	//		{json:TokenResponse}

	//TODO: Parse the scopes
	//TODO: Validate the scopes with the client
	//TODO: Parse the refresh token
	//TODO: Get the access token by refresh token
	//TODO: Validate the scope with access token
	//TODO: Generate the access token
	//TODO: Return access token
}
