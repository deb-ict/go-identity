package oauth

import (
	"mime"
	"net/http"
	"net/url"

	"github.com/deb-ict/go-identity/pkg/identity"
)

const maxFormSize = 64 << 10

// Param returns a single parameter value. Parameters must not be included more than once
// (RFC 6749 section 3.1 and 3.2). An absent parameter returns an empty string.
func Param(values url.Values, name string) (string, *Error) {
	v := values[name]
	if len(v) > 1 {
		return "", NewError(ErrorInvalidRequest, "the "+name+" parameter is included more than once")
	}
	if len(v) == 1 {
		return v[0], nil
	}
	return "", nil
}

// RequiredParam returns a single, non-empty parameter value.
func RequiredParam(values url.Values, name string) (string, *Error) {
	v, err := Param(values, name)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", NewError(ErrorInvalidRequest, "the "+name+" parameter is missing")
	}
	return v, nil
}

// parsePostForm parses an application/x-www-form-urlencoded request body.
// Only body parameters are returned: credentials must not be sent in the query string.
func parsePostForm(w http.ResponseWriter, r *http.Request) (url.Values, *Error) {
	if r.Method != http.MethodPost {
		return nil, NewError(ErrorInvalidRequest, "the request method must be POST")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, NewError(ErrorInvalidRequest, "the content type must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseForm(); err != nil {
		return nil, NewError(ErrorInvalidRequest, "the request body is malformed")
	}
	return r.PostForm, nil
}

// resolveScopes validates the requested scope against the client (RFC 6749 section 3.3).
// When the scope is omitted, the default scopes of the client are used.
func resolveScopes(client *identity.Client, scope string) ([]string, *Error) {
	if scope == "" {
		return append([]string{}, client.DefaultScopes...), nil
	}
	scopes := identity.ParseScope(scope)
	if !identity.ValidateScopeSyntax(scopes) {
		return nil, NewError(ErrorInvalidScope, "the requested scope is malformed")
	}
	if !client.ValidateScopes(scopes) {
		return nil, NewError(ErrorInvalidScope, "the requested scope is not allowed for this client")
	}
	return scopes, nil
}
