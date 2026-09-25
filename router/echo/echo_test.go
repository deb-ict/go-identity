package echorouter_test

import (
	"net/http"
	"testing"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/router/routertest"
	echorouter "github.com/deb-ict/go-identity/router/echo"
	"github.com/labstack/echo/v4"
)

func TestConformance(t *testing.T) {
	routertest.Run(t, func(t *testing.T) (router.Router, http.Handler) {
		e := echo.New()
		return echorouter.New(e), e
	})
}

func TestConformanceGroup(t *testing.T) {
	routertest.Run(t, func(t *testing.T) (router.Router, http.Handler) {
		e := echo.New()
		return echorouter.New(e.Group("")), e
	})
}
