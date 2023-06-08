package grant_type

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	mock_oauth "github.com/deb-ict/go-identity/mock/oauth"
	"github.com/deb-ict/go-identity/pkg/oauth"
	"github.com/golang/mock/gomock"
)

func Test_ClientCredentialsGrantType_HandleRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{}

	data := url.Values{}
	data.Set("scope", "api.read api.write")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, nil, gomock.Any()).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(1)

	grantType := NewClientCredentialsGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err != nil {
		t.Errorf("Failed to handle client credentials grant type: got error %v, expected nil", err)
	}
	if accessTokenResult != accessToken {
		t.Error("Failed to handle client credentials grant type: unexpected access token")
	}
	if refreshTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected refresh token")
	}
}

func Test_ClientCredentialsGrantType_HandleRequest_NoScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{}

	data := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, nil, gomock.Any()).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(1)

	grantType := NewClientCredentialsGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err != nil {
		t.Errorf("Failed to handle client credentials grant type: got error %v, expected nil", err)
	}
	if accessTokenResult != accessToken {
		t.Error("Failed to handle client credentials grant type: unexpected access token")
	}
	if refreshTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected refresh token")
	}
}

func Test_ClientCredentialsGrantType_HandleRequest_EmptyScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{}

	data := url.Values{}
	data.Set("scope", "")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, nil, gomock.Any()).
		Return(accessToken, nil).
		Times(0)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(0)

	grantType := NewClientCredentialsGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err == nil || err.Error() != "invalid_request" {
		t.Errorf("Failed to handle client credentials grant type: got error %v, expected invalid_request", err)
	}
	if accessTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected access token")
	}
	if refreshTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected refresh token")
	}
}

func Test_ClientCredentialsGrantType_HandleRequest_InvalidScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{}

	data := url.Values{}
	data.Set("scope", "api.invalid")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, nil, gomock.Any()).
		Return(accessToken, nil).
		Times(0)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(0)

	grantType := NewClientCredentialsGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err == nil || err.Error() != "invalid_request" {
		t.Errorf("Failed to handle client credentials grant type: got error %v, expected invalid_request", err)
	}
	if accessTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected access token")
	}
	if refreshTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected refresh token")
	}
}

func Test_ClientCredentialsGrantType_HandleRequest_MultipleScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{}

	data := url.Values{}
	data.Add("scope", "api.read api.write")
	data.Add("scope", "api.delete")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, nil, gomock.Any()).
		Return(accessToken, nil).
		Times(0)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(0)

	grantType := NewClientCredentialsGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err == nil || err.Error() != "invalid_request" {
		t.Errorf("Failed to handle client credentials grant type: got error %v, expected invalid_request", err)
	}
	if accessTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected access token")
	}
	if refreshTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected refresh token")
	}
}

func Test_ClientCredentialsGrantType_HandleRequest_GetAccessToken_Fails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		AllowedScopes: []string{"api.read", "api.write"},
	}
	accessToken := &oauth.AccessToken{}

	data := url.Values{}
	data.Set("scope", "api.read api.write")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, nil, gomock.Any()).
		Return(nil, errors.New("test error")).
		Times(1)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(accessToken, nil).
		Times(0)

	grantType := NewClientCredentialsGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err == nil || err.Error() != "test error" {
		t.Errorf("Failed to handle client credentials grant type: got error %v, expected test error", err)
	}
	if accessTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected access token")
	}
	if refreshTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected refresh token")
	}
}

func Test_ClientCredentialsGrantType_HandleRequest_CreateAccessToken_Fails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		AllowedScopes: []string{"api.read", "api.write"},
	}
	accessToken := &oauth.AccessToken{}

	data := url.Values{}
	data.Set("scope", "api.read api.write")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GenerateAccessToken(gomock.Any(), client, nil, gomock.Any()).
		Return(accessToken, nil).
		Times(1)
	svc.EXPECT().
		CreateAccessToken(gomock.Any(), accessToken).
		Return(nil, errors.New("test error")).
		Times(1)

	grantType := NewClientCredentialsGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err == nil || err.Error() != "test error" {
		t.Errorf("Failed to handle client credentials grant type: got error %v, expected test error", err)
	}
	if accessTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected access token")
	}
	if refreshTokenResult != nil {
		t.Error("Failed to handle client credentials grant type: unexpected refresh token")
	}
}
