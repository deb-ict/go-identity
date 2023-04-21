package main

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
)

func authorizationCodeTokenHandler(w http.ResponseWriter, r *http.Request, client *identity.Client) {
	//https://www.rfc-editor.org/rfc/rfc6749#section-4.1
	//		POST /token HTTP/1.1
	//		Host: server.example.com
	//		Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
	//		Content-Type: application/x-www-form-urlencoded
	//		grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	//REQUEST
	//	grant_type				REQUIRED			must be "authorization_code"
	//	code					REQUIRED
	//	redirect_uri			REQUIRED
	//	client_id				REQUIRED
	//RESPONSE
	//		HTTP/1.1 200 OK
	//		Content-Type: application/json;charset=UTF-8
	//		Cache-Control: no-store
	//		Pragma: no-cache
	//		{json:TokenResponse}
	//ERROR
	//	?

	//TODO: Parse the code
	//TODO: Get authorization code
	//TODO: Validate the authorization code
	//TODO: Get the user
	//TODO: Delete authorization code
	//TODO: Generate the access token
	//TODO: Return access token
}
