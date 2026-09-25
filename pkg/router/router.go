// Package router abstracts the HTTP router, so the identity server can be mounted
// on any router: net/http ServeMux, chi, gin, httprouter, gorilla/mux, echo, ...
//
// Routes are registered with a method and a canonical pattern using '{name}'
// placeholders for path segments, for example "/api/clients/{id}". Adapters convert
// the pattern to the syntax of their router (see ColonPattern) and expose the path
// parameters to the handler with WithParams, so handlers can read them with Param.
//
// Adapters for third party routers live in separate modules (router/chi, router/gin,
// router/httprouter, router/gorillamux, router/echo) so the core has no dependency on them.
package router

import (
	"context"
	"net/http"
	"strings"
)

// Router registers handlers for a method and a canonical pattern.
type Router interface {
	Handle(method string, pattern string, handler http.Handler)
}

// RouterFunc adapts a function to the Router interface.
type RouterFunc func(method string, pattern string, handler http.Handler)

func (f RouterFunc) Handle(method string, pattern string, handler http.Handler) {
	f(method, pattern, handler)
}

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

type paramsKey struct{}

// Params holds the path parameters of a request.
type Params map[string]string

// WithParams returns a request that carries the path parameters. Adapters call this
// before invoking the handler.
func WithParams(r *http.Request, params Params) *http.Request {
	if len(params) == 0 {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), paramsKey{}, params))
}

// Param returns the value of a path parameter. It checks the parameters attached with
// WithParams and falls back to the net/http ServeMux path values.
func Param(r *http.Request, name string) string {
	if params, ok := r.Context().Value(paramsKey{}).(Params); ok {
		if value, ok := params[name]; ok {
			return value
		}
	}
	return r.PathValue(name)
}

// ColonPattern converts a canonical pattern to the ':name' syntax used by gin,
// echo and httprouter: "/api/clients/{id}" becomes "/api/clients/:id".
func ColonPattern(pattern string) string {
	var b strings.Builder
	for {
		start := strings.IndexByte(pattern, '{')
		if start < 0 {
			b.WriteString(pattern)
			return b.String()
		}
		end := strings.IndexByte(pattern[start:], '}')
		if end < 0 {
			b.WriteString(pattern)
			return b.String()
		}
		b.WriteString(pattern[:start])
		b.WriteByte(':')
		b.WriteString(pattern[start+1 : start+end])
		pattern = pattern[start+end+1:]
	}
}

// ParamNames returns the parameter names of a canonical pattern in order.
func ParamNames(pattern string) []string {
	names := []string{}
	for {
		start := strings.IndexByte(pattern, '{')
		if start < 0 {
			return names
		}
		end := strings.IndexByte(pattern[start:], '}')
		if end < 0 {
			return names
		}
		names = append(names, pattern[start+1:start+end])
		pattern = pattern[start+end+1:]
	}
}

// WithPrefix returns a router that prefixes every pattern.
func WithPrefix(r Router, prefix string) Router {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return r
	}
	return RouterFunc(func(method string, pattern string, handler http.Handler) {
		r.Handle(method, prefix+pattern, handler)
	})
}

// WithMiddleware returns a router that wraps every handler with the middleware.
// The first middleware is the outermost.
func WithMiddleware(r Router, middleware ...Middleware) Router {
	return RouterFunc(func(method string, pattern string, handler http.Handler) {
		for i := len(middleware) - 1; i >= 0; i-- {
			handler = middleware[i](handler)
		}
		r.Handle(method, pattern, handler)
	})
}

// ServeMux adapts the net/http ServeMux (Go 1.22+ patterns) to the Router interface.
type ServeMux struct {
	Mux *http.ServeMux
}

// NewServeMux creates a router backed by a new http.ServeMux.
func NewServeMux() *ServeMux {
	return &ServeMux{Mux: http.NewServeMux()}
}

// Handle registers the handler. The canonical pattern is native ServeMux syntax.
// A pattern that ends with '/' is registered as an exact match.
func (m *ServeMux) Handle(method string, pattern string, handler http.Handler) {
	if strings.HasSuffix(pattern, "/") {
		pattern += "{$}"
	}
	m.Mux.Handle(method+" "+pattern, handler)
}

func (m *ServeMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.Mux.ServeHTTP(w, r)
}
