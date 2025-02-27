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

func Test_AuthorizationCodeGrantType_HandleRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := &oauth.Client{
		ClientId:      "test_client",
		AllowedScopes: []string{"api.read", "api.write", "api.delete"},
	}
	authorizationCode := &oauth.AuthorizationCode{
		Id:          "1",
		UserId:      "1",
		ClientId:    "test_client",
		RedirectUri: "/callback",
		CreatedAt:   time.Now().UTC(),
		Lifetime:    60 * time.Minute,
		Scopes:      []string{"api.read"},
	}
	accessToken := &oauth.AccessToken{}
	refreshToken := &oauth.RefreshToken{}
	user := &oauth.User{}

	data := url.Values{}
	data.Set("scope", "api.read api.write")
	data.Set("code", "test_code")
	data.Set("redirect_uri", "/callback")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	svc := mock_oauth.NewMockOAuthService(ctrl)
	svc.EXPECT().
		GetAuthorizationCodeByCode(gomock.Any(), "test_code").
		Return(authorizationCode, nil).
		Times(1)
	svc.EXPECT().
		GetUserById(gomock.Any(), "1").
		Return(user, nil).
		Times(1)
	svc.EXPECT().
		DeleteAuthorizationCode(gomock.Any(), "1").
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

	grantType := NewAuthorizationCodeGrantType(svc)

	accessTokenResult, refreshTokenResult, err := grantType.HandleRequest(client, req)
	if err != nil {
		t.Errorf("Failed to handle authorization code grant type: got error %v, expected nil", err)
	}
	if accessTokenResult != accessToken {
		t.Error("Failed to handle authorization code grant type: unexpected access token")
	}
	if refreshTokenResult != refreshToken {
		t.Error("Failed to handle authorization code grant type: unexpected refresh token")
	}
}

func Test_AuthorizationCodeGrantType_HandleRequest_NoCode(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_EmptyCode(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_MultipleCode(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_CodeExpired(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_InvalidClientId(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_InvalidRedirectUri(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_NoRedirectUri(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_MultipleRedirectUri(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_GetAuthorizationCodeByCode_Fails(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_GetUserById_Fails(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_DeleteAuthorizationCode_Fails(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_GenerateAccessToken_Fails(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_CreateAccessToken_Fails(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_GenerateRefreshToken_Fails(t *testing.T) {

}

func Test_AuthorizationCodeGrantType_HandleRequest_CreateRefreshToken_Fails(t *testing.T) {

}
