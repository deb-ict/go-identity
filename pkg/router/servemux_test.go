package router_test

import (
	"net/http"
	"testing"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/router/routertest"
)

func TestServeMuxConformance(t *testing.T) {
	routertest.Run(t, func(t *testing.T) (router.Router, http.Handler) {
		mux := router.NewServeMux()
		return mux, mux
	})
}
