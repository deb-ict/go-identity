package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

var (
	ClientStoreInstance ClientStore
)

type GrantTypeHandler func(w http.ResponseWriter, r *http.Request, client *Client)

func main() {
	ClientStoreInstance = NewClientStore()

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/auth/authorize", AuthorizeHandler).Methods("GET")
	router.HandleFunc("/auth/token", TokenHandler).Methods("POST")
	router.HandleFunc("/auth/revoke", RevocationHandler).Methods("POST")
	router.HandleFunc("/auth/introspect", IntrospectHandler).Methods("POST")
	router.HandleFunc("/auth/userinfo", UserInfoHandler).Methods("GET")
	router.HandleFunc("/auth/endsession", EndSessionHandler).Methods("GET")
	router.HandleFunc("/.well-known/openid-configuration", WellKnownConfigurationHandler).Methods("GET")

	router.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Callback invoked\n")
	})

	http.ListenAndServe(":5000", router)
}
