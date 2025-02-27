package grant_type

import (
	"context"
	"errors"
	"net/http"
	"time"

	oauth_http "github.com/deb-ict/go-identity/pkg/http"
	"github.com/deb-ict/go-identity/pkg/oauth"
)

func NewRefreshTokenGrantType(svc oauth.OAuthService) oauth.GrantTypeHandler {
	return &refreshTokenGrantType{
		svc: svc,
	}
}

type refreshTokenGrantType struct {
	svc oauth.OAuthService
}

func (grantType *refreshTokenGrantType) HandleRequest(client *oauth.Client, r *http.Request) (*oauth.AccessToken, *oauth.RefreshToken, error) {
	ctx := r.Context()

	// Validate the scope request parameter
	scopes, err := oauth_http.GetScopesParam(r)
	if err != nil {
		return nil, nil, err
	}
	if !client.ValidateScopes(scopes) {
		return nil, nil, errors.New("invalid_request")
	}

	// Get the refresh from request parameters
	token, err := oauth_http.GetStringParam(r, "refresh_token")
	if err != nil {
		return nil, nil, err
	}

	// Lookup the refresh token
	refreshToken, err := grantType.svc.GetRefreshTokenByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	// Validate the refresh token
	if refreshToken.ClientId != client.ClientId {
		return nil, nil, errors.New("invalid_request")
	}
	if refreshToken.HasExpired() {
		return nil, nil, errors.New("invalid_request")
	}

	// Validate the scopes
	if refreshToken.ValidateScopes(scopes) {
		return nil, nil, errors.New("invalid_request")
	}

	// Delete the old access token
	err = grantType.svc.DeleteAccessToken(ctx, refreshToken.AccessTokenId)
	if err != nil {
		return nil, nil, err
	}

	// Lookup the user
	user, err := grantType.svc.GetUserById(ctx, refreshToken.UserId)
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

	// Update the refresh token
	refreshToken, err = grantType.updateRefreshToken(ctx, client, accessToken, refreshToken)
	if err != nil {
		return nil, nil, err
	}

	// Return the access & refresh token
	return accessToken, refreshToken, nil
}

func (grantType *refreshTokenGrantType) updateRefreshToken(ctx context.Context, client *oauth.Client, accessToken *oauth.AccessToken, refreshToken *oauth.RefreshToken) (*oauth.RefreshToken, error) {
	var err error
	if refreshToken.TokenUsage == oauth.RefreshTokenUsageOneTime {
		// Delete the old refresh token
		err = grantType.svc.DeleteRefreshToken(ctx, refreshToken.Id)
		if err != nil {
			return nil, err
		}

		// Generate the refresh token
		refreshToken, err = grantType.svc.GenerateRefreshToken(ctx, client, accessToken)
		if err != nil {
			return nil, err
		}

		// Save the refresh token
		refreshToken, err = grantType.svc.CreateRefreshToken(ctx, refreshToken)
		if err != nil {
			return nil, err
		}
	} else {
		// Modify the existing token
		refreshToken.AccessTokenId = accessToken.Id
		refreshToken.UpdatedAt = time.Now().UTC()

		// Save the refresh token
		refreshToken, err = grantType.svc.UpdateRefreshToken(ctx, refreshToken.Id, refreshToken)
		if err != nil {
			return nil, err
		}
	}

	return refreshToken, nil
}
