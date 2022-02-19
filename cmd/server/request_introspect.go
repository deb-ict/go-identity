package main

import (
	"log"
	"net/http"
)

// OAuth 2.0 Token Introspection
// https://datatracker.ietf.org/doc/html/rfc7662
func IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("REQUEST: /auth/introspect")
}
