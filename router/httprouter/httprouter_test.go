package httprouteradapter_test

import (
	"net/http"
	"testing"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/router/routertest"
	httprouteradapter "github.com/deb-ict/go-identity/router/httprouter"
	"github.com/julienschmidt/httprouter"
)

func TestConformance(t *testing.T) {
	routertest.Run(t, func(t *testing.T) (router.Router, http.Handler) {
		r := httprouter.New()
		return httprouteradapter.New(r), r
	})
}
