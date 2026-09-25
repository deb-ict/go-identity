// Package muxrouter adapts a github.com/gorilla/mux router to router.Router.
//
// gorilla/mux uses the canonical '{name}' pattern syntax natively. The path
// parameters are read with mux.Vars and attached with router.WithParams, so handlers
// read them with router.Param.
//
// Usage:
//
//	r := mux.NewRouter()
//	server.RegisterRoutes(muxrouter.New(r))
//	http.ListenAndServe(":8080", r)
package muxrouter

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/gorilla/mux"
)

type adapter struct {
	r *mux.Router
}

// New returns a router.Router that registers routes on the gorilla/mux router
// (or a subrouter).
func New(r *mux.Router) router.Router {
	return &adapter{r: r}
}

func (a *adapter) Handle(method string, pattern string, handler http.Handler) {
	a.r.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		handler.ServeHTTP(w, router.WithParams(req, router.Params(mux.Vars(req))))
	})).Methods(method)
}
