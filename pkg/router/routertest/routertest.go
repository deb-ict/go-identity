// Package routertest contains a conformance test suite for router.Router adapters.
package routertest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deb-ict/go-identity/pkg/router"
)

// Factory returns a new router adapter and the http.Handler that serves its routes.
type Factory func(t *testing.T) (router.Router, http.Handler)

// Run registers the identity server route shapes on the router and checks the dispatching.
func Run(t *testing.T, factory Factory) {
	r, handler := factory(t)

	echo := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parts := []string{name, r.Method}
			for _, p := range []string{"id", "name"} {
				if v := router.Param(r, p); v != "" {
					parts = append(parts, p+"="+v)
				}
			}
			if r.Method == http.MethodPost {
				r.ParseForm()
				if v := r.PostForm.Get("field"); v != "" {
					parts = append(parts, "field="+v)
				}
			}
			w.Header().Set("X-Route", name)
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, strings.Join(parts, " "))
		})
	}

	r.Handle(http.MethodGet, "/", echo("home"))
	r.Handle(http.MethodGet, "/authorize", echo("authorize"))
	r.Handle(http.MethodPost, "/authorize", echo("authorize"))
	r.Handle(http.MethodPost, "/token", echo("token"))
	r.Handle(http.MethodGet, "/.well-known/oauth-authorization-server", echo("metadata"))
	r.Handle(http.MethodGet, "/password/forgot", echo("forgot"))
	r.Handle(http.MethodGet, "/api/clients", echo("clients"))
	r.Handle(http.MethodGet, "/api/clients/{id}", echo("client"))
	r.Handle(http.MethodPut, "/api/clients/{id}", echo("client"))
	r.Handle(http.MethodDelete, "/api/clients/{id}", echo("client"))
	r.Handle(http.MethodPost, "/api/clients/{id}/secret", echo("secret"))
	r.Handle(http.MethodGet, "/api/items/{id}/{name}", echo("item"))

	cases := []struct {
		method   string
		path     string
		body     string
		expected string
	}{
		{http.MethodGet, "/", "", "home GET"},
		{http.MethodGet, "/authorize?response_type=code", "", "authorize GET"},
		{http.MethodPost, "/authorize", "field=x", "authorize POST field=x"},
		{http.MethodPost, "/token", "field=y", "token POST field=y"},
		{http.MethodGet, "/.well-known/oauth-authorization-server", "", "metadata GET"},
		{http.MethodGet, "/password/forgot", "", "forgot GET"},
		{http.MethodGet, "/api/clients", "", "clients GET"},
		{http.MethodGet, "/api/clients/abc-123", "", "client GET id=abc-123"},
		{http.MethodPut, "/api/clients/abc", "", "client PUT id=abc"},
		{http.MethodDelete, "/api/clients/abc", "", "client DELETE id=abc"},
		{http.MethodPost, "/api/clients/xyz/secret", "", "secret POST id=xyz"},
		{http.MethodGet, "/api/items/1/two", "", "item GET id=1 name=two"},
	}
	for _, c := range cases {
		var body io.Reader
		if c.body != "" {
			body = strings.NewReader(c.body)
		}
		req := httptest.NewRequest(c.method, c.path, body)
		if c.body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != c.expected {
			t.Errorf("%s %s: expected 200 %q, got %d %q", c.method, c.path, c.expected, rec.Code, rec.Body.String())
		}
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/unknown"},
		{http.MethodGet, "/api/clients/abc/unknown"},
		{http.MethodGet, "/token"},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("%s %s: expected an error status, got 200 %q", c.method, c.path, rec.Body.String())
		}
	}
}
