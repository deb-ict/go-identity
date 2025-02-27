package grant_type

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	mock_oauth "github.com/deb-ict/go-identity/mock/oauth"
	"github.com/deb-ict/go-identity/pkg/oauth"
	"github.com/golang/mock/gomock"
)

func Test_RefreshTokenGrantType_HandleRequest_OneTimeToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		ClientId:      "test_client",
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{
		Id: "2",
	}
	refreshToken := &oauth.RefreshToken{
		Id:              "1",
		ClientId:        "test_client",
		AccessTokenId:   "1",
		UserId:          "1",
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		Lifetime:        60 * time.Minute,
		TokenUsage:      oauth.RefreshTokenUsageOneTime,
		TokenExpiration: oauth.RefreshTokenExpirationAbsolute,
	}
	user := &oauth.User{}

	data := url.Values{}
	data.Set("scope", "api.read api.write")
	data.Set("refresh_token", "test_token")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GetRefreshTokenByToken(gomock.Any(), "test_token").
		Return(refreshToken, nil).
		Times(1)
	svc.EXPECT().
		DeleteAccessToken(gomock.Any(), "1").
		Return(nil).
		Times(1)
	svc.EXPECT().
		GetUserById(gomock.Any(), "1").
		Return(user, nil).
		Times(1)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, user, gomock.Any()).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		DeleteRefreshToken(gomock.Any(), "1").
		Return(nil).
		Times(1)
	svc.EXPECT().
		GenerateRefreshToken(gomock.Any(), client, accessToken).
		Return(refreshToken, nil).
		Times(1)
	svc.EXPECT().
		CreateRefreshToken(gomock.Any(), refreshToken).
		Return(refreshToken, nil).
		Times(1)

	grantType := NewRefreshTokenGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err != nil {
		t.Errorf("Failed to handle refresh token grant type: got error %v, expected nil", err)
	}
	if accessTokenResult != accessToken {
		t.Error("Failed to handle refresh token grant type: unexpected access token")
	}
	if refreshTokenResult != refreshToken {
		t.Error("Failed to handle refresh token grant type: unexpected refresh token")
	}
}

func Test_RefreshTokenGrantType_HandleRequest_ReUse_AbsoluteExpiration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	timestamp := time.Now().UTC()
	client := &oauth.Client{
		ClientId:      "test_client",
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{
		Id: "2",
	}
	refreshToken := &oauth.RefreshToken{
		Id:              "1",
		ClientId:        "test_client",
		AccessTokenId:   "1",
		UserId:          "1",
		CreatedAt:       timestamp,
		UpdatedAt:       timestamp,
		Lifetime:        60 * time.Minute,
		TokenUsage:      oauth.RefreshTokenUsageReUse,
		TokenExpiration: oauth.RefreshTokenExpirationAbsolute,
	}
	user := &oauth.User{}

	data := url.Values{}
	data.Set("scope", "api.read api.write")
	data.Set("refresh_token", "test_token")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GetRefreshTokenByToken(gomock.Any(), "test_token").
		Return(refreshToken, nil).
		Times(1)
	svc.EXPECT().
		DeleteAccessToken(gomock.Any(), "1").
		Return(nil).
		Times(1)
	svc.EXPECT().
		GetUserById(gomock.Any(), "1").
		Return(user, nil).
		Times(1)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, user, gomock.Any()).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		UpdateRefreshToken(gomock.Any(), "1", refreshToken).
		Return(refreshToken, nil).
		Times(1)

	grantType := NewRefreshTokenGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err != nil {
		t.Errorf("Failed to handle refresh token grant type: got error %v, expected nil", err)
	}
	if accessTokenResult != accessToken {
		t.Error("Failed to handle refresh token grant type: unexpected access token")
	}
	if refreshTokenResult != refreshToken {
		t.Error("Failed to handle refresh token grant type: unexpected refresh token")
	}
	if refreshTokenResult != nil && refreshTokenResult.AccessTokenId != accessToken.Id {
		t.Errorf("Failed to handle refresh token grant type: access token id not change: got %v, expected %v", refreshTokenResult.AccessTokenId, accessToken.Id)
	}
	if refreshTokenResult != nil && refreshTokenResult.UpdatedAt == timestamp {
		t.Error("Failed to handle refresh token grant type: timestamp not changed")
	}
}

func Test_RefreshTokenGrantType_HandleRequest_ReUse_SlidingExpiration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	timestamp := time.Now().UTC()
	client := &oauth.Client{
		ClientId:      "test_client",
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{
		Id: "2",
	}
	refreshToken := &oauth.RefreshToken{
		Id:              "1",
		ClientId:        "test_client",
		AccessTokenId:   "1",
		UserId:          "1",
		CreatedAt:       timestamp,
		UpdatedAt:       timestamp,
		Lifetime:        60 * time.Minute,
		TokenUsage:      oauth.RefreshTokenUsageReUse,
		TokenExpiration: oauth.RefreshTokenExpirationSliding,
	}
	user := &oauth.User{}

	data := url.Values{}
	data.Set("scope", "api.read api.write")
	data.Set("refresh_token", "test_token")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GetRefreshTokenByToken(gomock.Any(), "test_token").
		Return(refreshToken, nil).
		Times(1)
	svc.EXPECT().
		DeleteAccessToken(gomock.Any(), "1").
		Return(nil).
		Times(1)
	svc.EXPECT().
		GetUserById(gomock.Any(), "1").
		Return(user, nil).
		Times(1)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, user, gomock.Any()).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		UpdateRefreshToken(gomock.Any(), "1", refreshToken).
		Return(refreshToken, nil).
		Times(1)

	grantType := NewRefreshTokenGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err != nil {
		t.Errorf("Failed to handle refresh token grant type: got error %v, expected nil", err)
	}
	if accessTokenResult != accessToken {
		t.Error("Failed to handle refresh token grant type: unexpected access token")
	}
	if refreshTokenResult != refreshToken {
		t.Error("Failed to handle refresh token grant type: unexpected refresh token")
	}
	if refreshTokenResult != nil && refreshTokenResult.AccessTokenId != accessToken.Id {
		t.Errorf("Failed to handle refresh token grant type: access token id not change: got %v, expected %v", refreshTokenResult.AccessTokenId, accessToken.Id)
	}
	if refreshTokenResult != nil && refreshTokenResult.UpdatedAt == timestamp {
		t.Error("Failed to handle refresh token grant type: timestamp not changed")
	}
}

func Test_RefreshTokenGrantType_HandleRequest_NoScope(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_EmptyScope(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_InvalidScope(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_MultipleScope(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_NoRefreshToken(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_EmptyRefreshToken(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_MultipleRefreshToken(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_TokenExpired(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_InvalidClientId(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_GetRefreshTokenByToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_DeleteAccessToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_GenerateAccessToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_CreateAccessToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_HandleRequest_UpdateRefreshToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_UpdateRefreshToken_OneTime(t *testing.T) {

}

func Test_RefreshTokenGrantType_UpdateRefreshToken_ReUse(t *testing.T) {

}

func Test_RefreshTokenGrantType_UpdateRefreshToken_OneTime_DeleteRefreshToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_UpdateRefreshToken_OneTime_GenerateRefreshToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_UpdateRefreshToken_OneTime_CreateRefreshToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_UpdateRefreshToken_ReUse_UpdateRefreshToken_Fails(t *testing.T) {

}

func Test_RefreshTokenGrantType_UpdateRefreshToken_AbsoluteExpiration_Timestamp_NotChanged(t *testing.T) {

}

func Test_RefreshTokenGrantType_UpdateRefreshToken_SlidingExpiration_Timestamp_Changed(t *testing.T) {

}
