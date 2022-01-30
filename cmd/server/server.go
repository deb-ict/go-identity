package main

import (
	"fmt"
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/gorilla/mux"
)

var (
	ClientSecretHasher identity.SecretHasher
	ClientStore        identity.ClientStore
	TokenManager       identity.TokenManager
)

func main() {
	ClientSecretHasher = identity.NewSecretHasher()
	ClientStore = NewClientStore()
	TokenManager = identity.NewJwtTokenManager()

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
