// Package ginrouter adapts a github.com/gin-gonic/gin engine or route group to
// router.Router.
//
// Canonical '{name}' patterns are converted to gin's ':name' syntax. The path
// parameters are attached with router.WithParams, so handlers read them with
// router.Param.
//
// Usage:
//
//	engine := gin.New()
//	server.RegisterRoutes(ginrouter.New(engine))
//	engine.Run(":8080")
package ginrouter

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/gin-gonic/gin"
)

type adapter struct {
	r gin.IRoutes
}

// New returns a router.Router that registers routes on the gin engine or group.
func New(r gin.IRoutes) router.Router {
	return &adapter{r: r}
}

func (a *adapter) Handle(method string, pattern string, handler http.Handler) {
	a.r.Handle(method, router.ColonPattern(pattern), func(c *gin.Context) {
		var params router.Params
		if len(c.Params) > 0 {
			params = make(router.Params, len(c.Params))
			for _, p := range c.Params {
				params[p.Key] = p.Value
			}
		}
		handler.ServeHTTP(c.Writer, router.WithParams(c.Request, params))
	})
}
