// Package chirouter adapts a github.com/go-chi/chi/v5 router to router.Router.
//
// chi uses the canonical '{name}' pattern syntax natively. The path parameters are
// read from the chi route context and attached with router.WithParams, so handlers
// read them with router.Param.
//
// Usage:
//
//	r := chi.NewRouter()
//	server.RegisterRoutes(chirouter.New(r))
//	http.ListenAndServe(":8080", r)
package chirouter

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/go-chi/chi/v5"
)

type adapter struct {
	r chi.Router
}

// New returns a router.Router that registers routes on the chi router.
func New(r chi.Router) router.Router {
	return &adapter{r: r}
}

func (a *adapter) Handle(method string, pattern string, handler http.Handler) {
	a.r.Method(method, pattern, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var params router.Params
		if rctx := chi.RouteContext(req.Context()); rctx != nil {
			keys, values := rctx.URLParams.Keys, rctx.URLParams.Values
			for i := 0; i < len(keys) && i < len(values); i++ {
				if params == nil {
					params = router.Params{}
				}
				params[keys[i]] = values[i]
			}
		}
		handler.ServeHTTP(w, router.WithParams(req, params))
	}))
}
