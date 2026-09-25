package session

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newManager(t *testing.T, now *time.Time) *Manager {
	m, err := NewManager(Options{Key: []byte(strings.Repeat("k", 32)), Lifetime: time.Hour, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func requestWithCookies(rec *httptest.ResponseRecorder) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestKeyLength(t *testing.T) {
	if _, err := NewManager(Options{Key: []byte("short")}); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestSession(t *testing.T) {
	now := time.Unix(1700000000, 0)
	m := newManager(t, &now)

	rec := httptest.NewRecorder()
	m.Create(rec, "user-1", "stamp")
	cookie := rec.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("expected HttpOnly, SameSite=Lax cookie")
	}

	s, ok := m.Get(requestWithCookies(rec))
	if !ok || s.UserId != "user-1" || s.SecurityStamp != "stamp" {
		t.Fatalf("unexpected session %+v %v", s, ok)
	}

	// Tampered
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: strings.Replace(cookie.Value, ".", "x.", 1)})
	if _, ok := m.Get(r); ok {
		t.Fatal("tampered cookie must be rejected")
	}

	// Signed with another key
	other, _ := NewManager(Options{Key: []byte(strings.Repeat("o", 32))})
	if _, ok := other.Get(requestWithCookies(rec)); ok {
		t.Fatal("cookie signed with another key must be rejected")
	}

	// Expired
	now = now.Add(2 * time.Hour)
	if _, ok := m.Get(requestWithCookies(rec)); ok {
		t.Fatal("expired session must be rejected")
	}

	// Destroy
	rec = httptest.NewRecorder()
	m.Destroy(rec)
	if rec.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatal("expected cookie removal")
	}
}

func TestCSRF(t *testing.T) {
	now := time.Now()
	m := newManager(t, &now)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	token := m.CSRFToken(rec, r)
	if token == "" || token != m.CSRFToken(rec, r) {
		t.Fatal("expected a stable token within a request")
	}

	post := func(token string, withCookie bool) bool {
		form := url.Values{CSRFFieldName: {token}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withCookie {
			for _, c := range rec.Result().Cookies() {
				req.AddCookie(c)
			}
		}
		return m.VerifyCSRF(req)
	}
	if !post(token, true) {
		t.Fatal("expected valid csrf token")
	}
	if post(token, false) {
		t.Fatal("token without cookie must be rejected")
	}
	if post("forged", true) {
		t.Fatal("forged token must be rejected")
	}
	if post("", true) {
		t.Fatal("missing token must be rejected")
	}
}
