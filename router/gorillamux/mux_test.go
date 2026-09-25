package muxrouter_test

import (
	"net/http"
	"testing"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/router/routertest"
	muxrouter "github.com/deb-ict/go-identity/router/gorillamux"
	"github.com/gorilla/mux"
)

func TestConformance(t *testing.T) {
	routertest.Run(t, func(t *testing.T) (router.Router, http.Handler) {
		r := mux.NewRouter()
		return muxrouter.New(r), r
	})
}
