package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/deb-ict/go-identity/database/mongo"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/gorilla/mux"
)

var (
	ClientSecretHasher identity.SecretHasher
	ClientStore        identity.ClientStore
	UserStore          identity.UserStore
	TokenManager       identity.TokenManager
)

func main() {
	ClientSecretHasher = identity.NewSecretHasher()

	// Initialize database
	db := mongo.NewDatabase()
	db.Open()
	defer db.Close()

	//
	clientPage, _ := db.GetClientStore().GetClients(context.TODO(), identity.ClientSearch{}, 0, 1)
	if clientPage.Count == 0 {
		clientSecret, _ := ClientSecretHasher.HashSecret("mysecret")
		client := identity.Client{
			ClientId:               "myclient",
			ClientSecret:           clientSecret,
			RedirectUris:           make([]string, 0),
			AllowedScopes:          make([]string, 0),
			RefreshTokenUsage:      identity.OneTimeRefreshTokenUsage,
			RefreshTokenExpiration: identity.SlidingRefreshTokenExpiration,
			RefreshTokenLifetime:   time.Minute * 15,
		}
		db.GetClientStore().CreateClient(context.TODO(), &client)
	}

	// Initialize the clients
	ClientStore = db.GetClientStore()
	UserStore = db.GetUserStore()

	TokenManager = identity.NewJwtTokenManager()

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/api/v1/client", GetClientsHandler).Methods("GET")
	router.HandleFunc("/api/v1/client/id", GetClientByIdHandler).Methods("GET")
	router.HandleFunc("/api/v1/client", CreateClientHandler).Methods("POST")
	router.HandleFunc("/api/v1/client/id", UpdateClientHandler).Methods("PUT")
	router.HandleFunc("/api/v1/client/id", DeleteClientHandler).Methods("DELETE")

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
