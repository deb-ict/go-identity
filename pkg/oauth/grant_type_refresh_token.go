package oauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

func NewRefreshTokenGrantType(svc OAuthService) GrantTypeHandler {
	return &refreshTokenGrantType{
		svc: svc,
	}
}

type refreshTokenGrantType struct {
	svc OAuthService
}

func (grantType *refreshTokenGrantType) HandleRequest(client *Client, r *http.Request) (*AccessToken, *RefreshToken, error) {
	ctx := r.Context()

	// Validate the scope request parameter
	scopes, err := getScopesParam(r)
	if err != nil {
		return nil, nil, err
	}
	if !client.ValidateScopes(scopes) {
		return nil, nil, errors.New("invalid_request")
	}

	// Get the refresh from request parameters
	token, err := getStringParam(r, "refresh_token")
	if err != nil {
		return nil, nil, err
	}

	// Lookup the refresh token
	refreshToken, err := grantType.svc.GetRefreshTokenByToken(ctx, token)
	if err != nil {
		return nil, nil, err
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

func (grantType *refreshTokenGrantType) updateRefreshToken(ctx context.Context, client *Client, accessToken *AccessToken, refreshToken *RefreshToken) (*RefreshToken, error) {
	var err error
	if refreshToken.TokenUsage == RefreshTokenUsageOneTime {
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
		if refreshToken.TokenExpiration == RefreshTokenExpirationSliding {
			refreshToken.UpdatedAt = time.Now().UTC()
		}

		// Save the refresh token
		refreshToken, err = grantType.svc.UpdateRefreshToken(ctx, refreshToken.Id, refreshToken)
		if err != nil {
			return nil, err
		}
	}

	return refreshToken, nil
}
