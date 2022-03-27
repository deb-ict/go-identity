package wip

import (
	"log"
	"net/http"
)

// OpenID Connect Discovery
// https://openid.net/specs/openid-connect-discovery-1_0.html
func WellKnownConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("REQUEST: /.well-known/openid-configuration")
}
