package wip

import (
	"log"
	"net/http"
)

// OAuth 2.0 Token Revocation
// https://datatracker.ietf.org/doc/html/rfc7009
func RevocationHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("REQUEST: /auth/revoke")
}
