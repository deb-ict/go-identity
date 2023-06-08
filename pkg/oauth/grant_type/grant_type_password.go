package grant_type

import (
	"errors"
	"net/http"

	oauth_http "github.com/deb-ict/go-identity/pkg/http"
	"github.com/deb-ict/go-identity/pkg/oauth"
)

func NewPasswordGrantType(svc oauth.OAuthService) oauth.GrantTypeHandler {
	return &passwordGrantType{
		svc: svc,
	}
}

type passwordGrantType struct {
	svc oauth.OAuthService
}

func (grantType *passwordGrantType) HandleRequest(client *oauth.Client, r *http.Request) (*oauth.AccessToken, *oauth.RefreshToken, error) {
	ctx := r.Context()

	// Validate the scope request parameter
	scopes, err := oauth_http.GetScopesParam(r)
	if err != nil {
		return nil, nil, err
	}
	if !client.ValidateScopes(scopes) {
		return nil, nil, errors.New("invalid_request")
	}

	// Get the username and password from request parameters
	username, err := oauth_http.GetStringParam(r, "username")
	if err != nil {
		return nil, nil, err
	}
	password, err := oauth_http.GetStringParam(r, "password")
	if err != nil {
		return nil, nil, err
	}

	// Lookup the user
	user, err := grantType.svc.GetUserByUserName(ctx, username)
	if err != nil {
		return nil, nil, err
	}

	// Validate the password
	err = grantType.svc.VerifyUserPassword(ctx, user, password)
	if err != nil {
		return nil, nil, err
	}

	// Generate a new access token
	accessToken, err := grantType.svc.GenerateAccessToken(ctx, client, user, scopes)
	if err != nil {
		return nil, nil, err
	}

	// Save the access token
	accessToken, err = grantType.svc.CreateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, nil, err
	}

	// Generate the refresh token
	refreshToken, err := grantType.svc.GenerateRefreshToken(ctx, client, accessToken)
	if err != nil {
		return nil, nil, err
	}

	// Save the refresh token
	refreshToken, err = grantType.svc.CreateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, nil, err
	}

	// Return the access & refresh token
	return accessToken, refreshToken, nil
}
