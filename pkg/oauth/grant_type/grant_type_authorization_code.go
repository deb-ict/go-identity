package grant_type

import (
	"errors"
	"net/http"

	oauth_http "github.com/deb-ict/go-identity/pkg/http"
	"github.com/deb-ict/go-identity/pkg/oauth"
)

func NewAuthorizationCodeGrantType(svc oauth.OAuthService) oauth.GrantTypeHandler {
	return &authorizationCodeGrantType{
		svc: svc,
	}
}

type authorizationCodeGrantType struct {
	svc oauth.OAuthService
}

func (grantType *authorizationCodeGrantType) HandleRequest(client *oauth.Client, r *http.Request) (*oauth.AccessToken, *oauth.RefreshToken, error) {
	ctx := r.Context()

	// Get the code from request parameters
	code, err := oauth_http.GetStringParam(r, "code")
	if err != nil {
		return nil, nil, err
	}

	// Lookup the authorization code
	authorizationCode, err := grantType.svc.GetAuthorizationCodeByCode(ctx, code)
	if err != nil {
		return nil, nil, err
	}

	// Validate the authorization code
	if authorizationCode.ClientId != client.ClientId {
		return nil, nil, errors.New("invalid_request")
	}
	if authorizationCode.HasExpired() {
		return nil, nil, errors.New("invalid_request")
	}
	if authorizationCode.RedirectUri != "" {
		redirectUri := r.Form["redirect_uri"]
		if len(redirectUri) != 1 || !authorizationCode.ValidateRedirectUri(redirectUri[0]) {
			return nil, nil, errors.New("invalid_request")
		}
	}

	// Lookup the user
	user, err := grantType.svc.GetUserById(ctx, authorizationCode.UserId)
	if err != nil {
		return nil, nil, err
	}

	// Delete the authorization code
	err = grantType.svc.DeleteAuthorizationCode(ctx, authorizationCode.Id)
	if err != nil {
		return nil, nil, err
	}

	// Generate a new access token
	accessToken, err := grantType.svc.GenerateAccessToken(ctx, client, user, authorizationCode.Scopes)
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
