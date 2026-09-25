package router

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestColonPattern(t *testing.T) {
	cases := map[string]string{
		"/":                         "/",
		"/token":                    "/token",
		"/api/clients/{id}":         "/api/clients/:id",
		"/api/clients/{id}/secret":  "/api/clients/:id/secret",
		"/a/{x}/b/{y}":              "/a/:x/b/:y",
		"/broken/{x":                "/broken/{x",
		"/.well-known/oauth-server": "/.well-known/oauth-server",
	}
	for input, expected := range cases {
		if got := ColonPattern(input); got != expected {
			t.Errorf("ColonPattern(%q) = %q, expected %q", input, got, expected)
		}
	}
}

func TestParamNames(t *testing.T) {
	if got := ParamNames("/a/{x}/b/{y}"); !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Fatalf("unexpected names: %v", got)
	}
	if got := ParamNames("/a"); len(got) != 0 {
		t.Fatalf("unexpected names: %v", got)
	}
}

func TestParamFromContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if Param(r, "id") != "" {
		t.Fatal("expected empty param")
	}
	r = WithParams(r, Params{"id": "42"})
	if Param(r, "id") != "42" {
		t.Fatal("expected param from context")
	}
}

func TestServeMux(t *testing.T) {
	mux := NewServeMux()
	var r Router = mux
	r = WithPrefix(r, "/identity/")
	calls := []string{}
	r = WithMiddleware(r,
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, "outer")
				next.ServeHTTP(w, r)
			})
		},
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, "inner")
				next.ServeHTTP(w, r)
			})
		},
	)
	r.Handle(http.MethodGet, "/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "home")
	}))
	r.Handle(http.MethodGet, "/items/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "item "+Param(r, "id"))
	}))

	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}

	if code, body := get("/identity/items/7"); code != 200 || body != "item 7" {
		t.Fatalf("unexpected response %d %q", code, body)
	}
	if code, body := get("/identity/"); code != 200 || body != "home" {
		t.Fatalf("unexpected response %d %q", code, body)
	}
	if code, _ := get("/identity/unknown"); code != 404 {
		t.Fatalf("expected 404 for unknown path, got %d", code)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/identity/items/7", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if !reflect.DeepEqual(calls[:2], []string{"outer", "inner"}) {
		t.Fatalf("unexpected middleware order: %v", calls)
	}
}
