package main

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
)

func tokenAuthorizeHandler(w http.ResponseWriter, r *http.Request, client *identity.Client, state string, redirectUri string, scopes []string) {
	//https://www.rfc-editor.org/rfc/rfc6749#section-4.2
	//REQUEST
	//		GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
	//		Host: server.example.com
	//	response_type			REQUIRED			must be "token"
	//	client_id				REQUIRED
	//	redirect_uri			OPTIONAL
	//	scope					OPTIONAL
	//	state					RECOMMENDED
	//RESPONSE
	//		HTTP/1.1 302 Found
	//		Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&expires_in=3600
	//	access_token			REQUIRED
	//	token_type				REQUIRED
	//	expires_in				RECOMMENDED
	//	scope					OPTIONAL
	//	state					REQUIRED
	//ERROR
	//		HTTP/1.1 302 Found
	//		Location: https://client.example.com/cb#error=access_denied&state=xyz
	//	error					REQUIRED
	//		invalid_request
	//		unauthorized_client
	//		access_denied
	//		unsupported_response_type
	//		invalid_scope
	//		server_error
	//		temporarily_unavailable
	//	error_description		OPTIONAL
	//	error_uri				OPTIONAL
	//	state					REQUIRED
}
