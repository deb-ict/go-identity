package chirouter_test

import (
	"net/http"
	"testing"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/router/routertest"
	chirouter "github.com/deb-ict/go-identity/router/chi"
	"github.com/go-chi/chi/v5"
)

func TestConformance(t *testing.T) {
	routertest.Run(t, func(t *testing.T) (router.Router, http.Handler) {
		r := chi.NewRouter()
		return chirouter.New(r), r
	})
}
