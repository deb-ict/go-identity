// Package echorouter adapts a github.com/labstack/echo/v4 instance or group to
// router.Router.
//
// Canonical '{name}' patterns are converted to echo's ':name' syntax. The path
// parameters are attached with router.WithParams, so handlers read them with
// router.Param.
//
// Usage:
//
//	e := echo.New()
//	server.RegisterRoutes(echorouter.New(e))
//	e.Start(":8080")
//
// A group can be used as well:
//
//	server.RegisterRoutes(echorouter.New(e.Group("/identity")))
package echorouter

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/labstack/echo/v4"
)

// Routes is implemented by *echo.Echo and *echo.Group.
type Routes interface {
	Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route
}

var (
	_ Routes = (*echo.Echo)(nil)
	_ Routes = (*echo.Group)(nil)
)

type adapter struct {
	r Routes
}

// New returns a router.Router that registers routes on the echo instance or group
// (*echo.Echo or *echo.Group).
func New(r Routes) router.Router {
	return &adapter{r: r}
}

func (a *adapter) Handle(method string, pattern string, handler http.Handler) {
	a.r.Add(method, router.ColonPattern(pattern), func(c echo.Context) error {
		names, values := c.ParamNames(), c.ParamValues()
		var params router.Params
		for i := 0; i < len(names) && i < len(values); i++ {
			if params == nil {
				params = make(router.Params, len(names))
			}
			params[names[i]] = values[i]
		}
		handler.ServeHTTP(c.Response(), router.WithParams(c.Request(), params))
		return nil
	})
}
