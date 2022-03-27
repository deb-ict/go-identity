package wip

import (
	"log"
	"net/http"
)

// OpenID UserInfo Endpoint
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
func UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("REQUEST: /auth/userinfo")
}
