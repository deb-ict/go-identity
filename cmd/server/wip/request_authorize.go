package wip

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/response"
)

// OAuth 2.0 Authorization Endpoint
// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	// Load the client
	client, err := ClientManager.GetClientFromRequest(w, r)
	if err != nil {
		return
	}

	// Parse the redirect uri
	redirectUri := r.FormValue("redirect_uri")
	if redirectUri == "" && len(client.RedirectUris) > 0 {
		redirectUri = client.RedirectUris[0]
	}
	parsedRedirectUri, _ := url.ParseRequestURI(redirectUri)

	// Get the requested scopes
	scope := r.FormValue("scope")
	scopes := strings.Split(scope, " ")

	// Handle the response type
	responseType := r.FormValue("response_type")
	switch responseType {
	case "code":
		CodeAuthorizeHandler(w, r, client, parsedRedirectUri, scopes)
	case "token":
		TokenAuthorizeHandler(w, r, client, parsedRedirectUri, scopes)
	default:
		response.UnsupportedResponseType(w)
	}

	//Response:
	//	- access_token			REQUIRED
	//	- token_type			REQUIRED
	//	- expires_in			RECOMMENDED
	//	- scope					OPTIONAL
	//	- state					REQUIRED
	//302
	//Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&expires_in=3600

	/*
		query := parsedUri.Query()
		query.Set("access_token", "web_access_token")
		query.Set("token_type", "bearer")
		query.Set("expires_in", "3600")

		target := fmt.Sprintf("%s?%s", parsedUri.String(), query.Encode())
		http.Redirect(w, r, target, http.StatusFound)
	*/
	/*
		loginPageUrl := "http://localhost:5000/account/login"
		loginPageUri, _ := url.ParseRequestURI(loginPageUrl)
		query := loginPageUri.Query()
		query.Set("code", "authorize_code")

		state := r.FormValue("state")
		if state != "" {
			query.Set("state", state)
		}

		target := fmt.Sprintf("%s?%s", parsedUri.String(), query.Encode())
		http.Redirect(w, r, target, http.StatusFound)
	*/
}

func CodeAuthorizeHandler(w http.ResponseWriter, r *http.Request, client *identity.Client, redirectUri *url.URL, scopes []string) {
	/*
		authCode := identity.AuthorizationCode{
			ClientId:        client.ClientId,
			RedirectUri:     redirectUri.String(),
			RequestedScopes: scopes,
			Lifetime:        time.Minute * 5,
			Code: "",
		}
	*/

	loginPageUri, _ := url.ParseRequestURI("http://localhost:5000/account/login")
	query := loginPageUri.Query()
	query.Set("code", "authorize_code")

	state := r.FormValue("state")
	if state != "" {
		query.Set("state", state)
	}

	target := fmt.Sprintf("%s?%s", loginPageUri.String(), query.Encode())
	http.Redirect(w, r, target, http.StatusFound)
}

func TokenAuthorizeHandler(w http.ResponseWriter, r *http.Request, client *identity.Client, redirectUri *url.URL, scopes []string) {

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
