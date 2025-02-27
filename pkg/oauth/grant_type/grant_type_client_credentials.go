package grant_type

import (
	"errors"
	"net/http"

	oauth_http "github.com/deb-ict/go-identity/pkg/http"
	"github.com/deb-ict/go-identity/pkg/oauth"
)

func NewClientCredentialsGrantType(svc oauth.OAuthService) oauth.GrantTypeHandler {
	return &clientCredentialsGrantType{
		svc: svc,
	}
}

type clientCredentialsGrantType struct {
	svc oauth.OAuthService
}

func (grantType *clientCredentialsGrantType) HandleRequest(client *oauth.Client, r *http.Request) (*oauth.AccessToken, *oauth.RefreshToken, error) {
	ctx := r.Context()

	// Validate the scope request parameter
	scopes, err := oauth_http.GetScopesParam(r)
	if err != nil {
		return nil, nil, err
	}
	if !client.ValidateScopes(scopes) {
		return nil, nil, errors.New("invalid_request")
	}

	// Generate a new access token
	accessToken, err := grantType.svc.GenerateAccessToken(ctx, client, nil, scopes)
	if err != nil {
		return nil, nil, err
	}

	// Save the access token
	accessToken, err = grantType.svc.CreateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, nil, err
	}

	// Return the access token
	return accessToken, nil, nil
}
