package grant_type

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	mock_oauth "github.com/deb-ict/go-identity/mock/oauth"
	"github.com/deb-ict/go-identity/pkg/oauth"
	"github.com/golang/mock/gomock"
)

func Test_PasswordGrantType_HandleRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	accessToken := &oauth.AccessToken{}
	refreshToken := &oauth.RefreshToken{}
	user := &oauth.User{}

	data := url.Values{}
	data.Set("scope", "api.read api.write")
	data.Set("username", "test_user")
	data.Set("password", "test_pass")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GetUserByUserName(gomock.Any(), "test_user").
		Return(user, nil).
		Times(1)
	svc.EXPECT().
		VerifyUserPassword(gomock.Any(), user, "test_pass").
		Return(nil).
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
		GenerateRefreshToken(gomock.Any(), client, accessToken).
		Return(refreshToken, nil).
		Times(1)
	svc.EXPECT().
		CreateRefreshToken(gomock.Any(), refreshToken).
		Return(refreshToken, nil).
		Times(1)

	grantType := NewPasswordGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err != nil {
		t.Errorf("Failed to handle password grant type: got error %v, expected nil", err)
	}
	if accessTokenResult != accessToken {
		t.Error("Failed to handle password grant type: unexpected access token")
	}
	if refreshTokenResult != refreshToken {
		t.Error("Failed to handle password grant type: unexpected refresh token")
	}
}

func Test_PasswordGrantType_HandleRequest_NoScope(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_InvalidScope(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_MultipleScope(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_NoUserName(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_EmptyUserName(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_MultipleUserName(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_NoPassword(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_EmptyPassword(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_MultiplePassword(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_GetUserByUserName_Fails(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_VerifyUserPassword_Fails(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_GenerateAccessToken_Fails(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_CreateAccessToken_Fails(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_GenerateRefreshToken_Fails(t *testing.T) {

}

func Test_PasswordGrantType_HandleRequest_CreateRefreshToken_Fails(t *testing.T) {

}
