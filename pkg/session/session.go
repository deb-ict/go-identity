// Package session implements the stateless, signed login session cookie and CSRF protection
// of the identity server UI.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/deb-ict/go-identity/pkg/security"
)

const (
	DefaultCookieName     = "identity_session"
	DefaultCSRFCookieName = "identity_csrf"
	CSRFFieldName         = "csrf_token"
	CSRFHeaderName        = "X-CSRF-Token"
)

// Session is the authenticated state stored in the session cookie.
type Session struct {
	UserId string `json:"uid"`
	// SecurityStamp of the user when the session was created. A session with an outdated
	// stamp (password changed, account disabled) is rejected by the caller.
	SecurityStamp string `json:"sst"`
	AuthTime      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

// Options configures the session manager.
type Options struct {
	// Key signs the cookies. It must have at least 32 bytes.
	Key            []byte
	CookieName     string
	CSRFCookieName string
	// Path of the cookies, defaults to "/".
	Path     string
	Domain   string
	Secure   bool
	Lifetime time.Duration
	Now      func() time.Time
}

// Manager creates and validates session cookies.
type Manager struct {
	opts Options
}

// NewManager creates a session manager.
func NewManager(opts Options) (*Manager, error) {
	if len(opts.Key) < 32 {
		return nil, errors.New("session: the key must have at least 32 bytes")
	}
	if opts.CookieName == "" {
		opts.CookieName = DefaultCookieName
	}
	if opts.CSRFCookieName == "" {
		opts.CSRFCookieName = DefaultCSRFCookieName
	}
	if opts.Path == "" {
		opts.Path = "/"
	}
	if opts.Lifetime <= 0 {
		opts.Lifetime = 8 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Manager{opts: opts}, nil
}

func (m *Manager) sign(purpose string, payload string) string {
	mac := hmac.New(sha256.New, m.opts.Key)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) cookie(name string, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     m.opts.Path,
		Domain:   m.opts.Domain,
		MaxAge:   maxAge,
		Secure:   m.opts.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// Create starts a session for the user.
func (m *Manager) Create(w http.ResponseWriter, userId string, securityStamp string) *Session {
	now := m.opts.Now()
	s := &Session{
		UserId:        userId,
		SecurityStamp: securityStamp,
		AuthTime:      now.Unix(),
		ExpiresAt:     now.Add(m.opts.Lifetime).Unix(),
	}
	data, _ := json.Marshal(s)
	payload := base64.RawURLEncoding.EncodeToString(data)
	value := payload + "." + m.sign("session", payload)
	http.SetCookie(w, m.cookie(m.opts.CookieName, value, int(m.opts.Lifetime.Seconds())))
	return s
}

// Get returns the valid session of the request.
func (m *Manager) Get(r *http.Request) (*Session, bool) {
	c, err := r.Cookie(m.opts.CookieName)
	if err != nil {
		return nil, false
	}
	payload, signature, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(signature), []byte(m.sign("session", payload))) {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, false
	}
	s := &Session{}
	if err := json.Unmarshal(data, s); err != nil || s.UserId == "" {
		return nil, false
	}
	if m.opts.Now().Unix() >= s.ExpiresAt {
		return nil, false
	}
	return s, true
}

// Destroy removes the session cookie.
func (m *Manager) Destroy(w http.ResponseWriter) {
	http.SetCookie(w, m.cookie(m.opts.CookieName, "", -1))
}

// CSRFToken returns the CSRF token of the request, and sets the CSRF cookie when needed.
// The token must be posted back in the csrf_token form field (or X-CSRF-Token header).
//
// It uses the signed double submit cookie pattern: the cookie holds a random value, the
// token is an HMAC of that value, so an attacker that can plant a cookie can't forge a token.
func (m *Manager) CSRFToken(w http.ResponseWriter, r *http.Request) string {
	value := m.csrfCookieValue(r)
	if value == "" {
		value = security.RandomToken(32)
		http.SetCookie(w, m.cookie(m.opts.CSRFCookieName, value, 0))
		// Make the cookie visible to later calls within the same request
		r.AddCookie(&http.Cookie{Name: m.opts.CSRFCookieName, Value: value})
	}
	return m.sign("csrf", value)
}

func (m *Manager) csrfCookieValue(r *http.Request) string {
	var value string
	for _, c := range r.Cookies() {
		if c.Name == m.opts.CSRFCookieName && len(c.Value) >= 32 {
			value = c.Value
		}
	}
	return value
}

// VerifyCSRF checks the CSRF token of a state changing request.
func (m *Manager) VerifyCSRF(r *http.Request) bool {
	value := m.csrfCookieValue(r)
	if value == "" {
		return false
	}
	token := r.Header.Get(CSRFHeaderName)
	if token == "" {
		token = r.PostFormValue(CSRFFieldName)
	}
	return token != "" && hmac.Equal([]byte(token), []byte(m.sign("csrf", value)))
}
