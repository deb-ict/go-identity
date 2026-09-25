// Package httprouteradapter adapts a github.com/julienschmidt/httprouter router to
// router.Router.
//
// Canonical '{name}' patterns are converted to httprouter's ':name' syntax. The path
// parameters are attached with router.WithParams, so handlers read them with
// router.Param.
//
// Usage:
//
//	r := httprouter.New()
//	server.RegisterRoutes(httprouteradapter.New(r))
//	http.ListenAndServe(":8080", r)
package httprouteradapter

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/julienschmidt/httprouter"
)

type adapter struct {
	r *httprouter.Router
}

// New returns a router.Router that registers routes on the httprouter router.
func New(r *httprouter.Router) router.Router {
	return &adapter{r: r}
}

func (a *adapter) Handle(method string, pattern string, handler http.Handler) {
	a.r.Handle(method, router.ColonPattern(pattern), func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		var params router.Params
		if len(ps) > 0 {
			params = make(router.Params, len(ps))
			for _, p := range ps {
				params[p.Key] = p.Value
			}
		}
		handler.ServeHTTP(w, router.WithParams(req, params))
	})
}
