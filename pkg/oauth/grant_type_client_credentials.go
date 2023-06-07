package oauth

import (
	"errors"
	"net/http"
)

func NewClientCredentialsGrantType(svc OAuthService) GrantTypeHandler {
	return &clientCredentialsGrantType{
		svc: svc,
	}
}

type clientCredentialsGrantType struct {
	svc OAuthService
}

func (grantType *clientCredentialsGrantType) HandleRequest(client *Client, r *http.Request) (*AccessToken, *RefreshToken, error) {
	ctx := r.Context()

	// Validate the scope request parameter
	scopes, err := getScopesParam(r)
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
