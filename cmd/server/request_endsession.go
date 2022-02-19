package main

import (
	"log"
	"net/http"
)

// GET /connect/endsession
// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
func EndSessionHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("REQUEST: /auth/endsession")
}
