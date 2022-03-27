package wip

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/deb-ict/go-identity/pkg/identity"
)

// OAuth 2.0 Authorization Endpoint
// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("REQUEST: /auth/authorize")

	//https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
	//The authorization server MUST NOT issue a refresh token.

	//Must be code?
	//Response type:
	//	- code		authorization code
	//	- token		implicit
	/*
		clientId := r.FormValue("client_id")
		redirectUri := r.FormValue("redirect_uri") //OPTIONAL
		scope := r.FormValue("scope")              //OPTIONAL
		state := r.FormValue("state")              //RECOMMENDED

		if redirectUri == "" {
			redirectUri = "http://localhost:5000/cb"
		}
	*/

	client, err := ClientManager.GetClientFromRequest(w, r)
	if err != nil {
		return
	}

	redirectUri := r.FormValue("redirect_uri")
	if redirectUri == "" && len(client.RedirectUris) > 0 {
		redirectUri = client.RedirectUris[0]
	}
	parsedUri, _ := url.ParseRequestURI(redirectUri)

	/*
		responseType := r.FormValue("response_type")
		switch responseType {
		case "code":
			CodeAuthorizeHandler(w, r, parsedUri, client)
		case "token":
			TokenAuthorizeHandler(w, r, parsedUri, client)
		default:
			return
		}
	*/

	//http://localhost:8080/web/authorize?
	//client_id=test_client_1&
	//redirect_uri=http://www.example.com
	//response_type=code
	//state=somestate
	//scope=read_write

	//TODO: Redirect to login page?

	//Response:
	//	- access_token			REQUIRED
	//	- token_type			REQUIRED
	//	- expires_in			RECOMMENDED
	//	- scope					OPTIONAL
	//	- state					REQUIRED
	//302
	//Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&expires_in=3600

	query := parsedUri.Query()
	query.Set("access_token", "web_access_token")
	query.Set("token_type", "bearer")
	query.Set("expires_in", "3600")

	target := fmt.Sprintf("%s?%s", parsedUri.String(), query.Encode())
	http.Redirect(w, r, target, http.StatusFound)
}

func CodeAuthorizeHandler(w http.ResponseWriter, r *http.Request, redirectUri *url.URL, client *identity.Client) {

	/*
		authCode := AuthorizationCode{
			ClientId: client.ClientId,
		}
	*/
}

func TokenAuthorizeHandler(w http.ResponseWriter, r *http.Request, redirectUri *url.URL, client *identity.Client) {

}

func codeErrorRedirect(w http.ResponseWriter, r *http.Request, redirectUri *url.URL, err string, state string) {
	query := redirectUri.Query()
	query.Set("error", err)
	if state != "" {
		query.Set("state", state)
	}
	queryString := "?" + query.Encode()
	if queryString == "?" {

	}
	encoded := query.Encode()
	if len(encoded) > 0 {
		encoded = "?" + encoded
	}
	target := fmt.Sprintf("%s%s", redirectUri.String(), encoded)
	http.Redirect(w, r, target, http.StatusFound)
}

func tokenErrorRedirect(w http.ResponseWriter, r *http.Request, redirectUri *url.URL, err string, state string) {
	query := redirectUri.Query()
	query.Set("error", err)
	if state != "" {
		query.Set("state", state)
	}
	encoded := query.Encode()
	target := fmt.Sprintf("%s#%s", redirectUri.String(), encoded)
	http.Redirect(w, r, target, http.StatusFound)
}
