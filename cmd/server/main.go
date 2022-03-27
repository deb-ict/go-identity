package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/deb-ict/go-identity/cmd/server/wip"
	"github.com/deb-ict/go-identity/database/mongo"
	"github.com/deb-ict/go-identity/internal/webhost"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func getConfigPath(configPath string) string {
	if len(configPath) == 0 {
		configPath = os.Getenv("CONFIG_PATH")
	}
	if len(configPath) == 0 {
		configPath = "/etc/go-identity/server.yaml"
	}
	return configPath
}

func handleAccountLoginGet(w http.ResponseWriter, r *http.Request) {

}

func handleAccountLoginPost(w http.ResponseWriter, r *http.Request) {

}

func main() {
	var err error

	// Parse arguments
	var configPath string
	var wait time.Duration
	flag.DurationVar(&wait, "graceful-timeout", time.Second*15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
	flag.StringVar(&configPath, "config", "", "the path of the configuration file")
	flag.Parse()

	// Load the environment config and get the correct config path
	if _, err := os.Stat(".env"); err == nil {
		godotenv.Load(".env")
	}
	configPath = getConfigPath(configPath)

	// Initialize database
	db := mongo.NewDatabase()
	err = db.GetConfig().Load(configPath)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Initialize the managers
	wip.ClientManager = identity.NewClientManager(db.GetClientStore())
	wip.UserManager = identity.NewUserManager(db.GetUserStore())

	// Set the default client
	clientPage, _ := wip.ClientManager.GetStore().GetClients(context.TODO(), identity.ClientSearch{}, 0, 1)
	if clientPage.Count == 0 {
		clientSecret, _ := wip.ClientManager.GetSecretHasher().HashSecret("mysecret")
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

	wip.TokenManager = identity.NewJwtTokenManager()

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/api/v1/client", wip.GetClientsHandler).Methods("GET")
	router.HandleFunc("/api/v1/client/id", wip.GetClientByIdHandler).Methods("GET")
	router.HandleFunc("/api/v1/client", wip.CreateClientHandler).Methods("POST")
	router.HandleFunc("/api/v1/client/id", wip.UpdateClientHandler).Methods("PUT")
	router.HandleFunc("/api/v1/client/id", wip.DeleteClientHandler).Methods("DELETE")

	router.HandleFunc("/auth/authorize", wip.AuthorizeHandler).Methods("GET")
	router.HandleFunc("/auth/token", wip.TokenHandler).Methods("POST")
	router.HandleFunc("/auth/revoke", wip.RevocationHandler).Methods("POST")
	router.HandleFunc("/auth/introspect", wip.IntrospectHandler).Methods("POST")
	router.HandleFunc("/auth/userinfo", wip.UserInfoHandler).Methods("GET")
	router.HandleFunc("/auth/endsession", wip.EndSessionHandler).Methods("GET")
	router.HandleFunc("/.well-known/openid-configuration", wip.WellKnownConfigurationHandler).Methods("GET")

	router.HandleFunc("/account/login", handleAccountLoginGet).Methods("GET")
	router.HandleFunc("/account/login", handleAccountLoginPost).Methods("POST")

	router.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Callback invoked\n")
	})

	// Initialize the webhost
	host := webhost.NewWebHost(router)
	err = host.GetConfig().Load(configPath)
	if err != nil {
		log.Fatal(err)
	}

	// Run the host
	host.Run()

	// Exit
	os.Exit(0)
}
