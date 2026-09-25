package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

// AuthenticateClient authenticates the client of a token, revocation or introspection request
// (RFC 6749 section 2.3.1 and 3.2.1).
//
// Confidential clients authenticate with HTTP Basic (client_secret_basic) or with the client_id and
// client_secret body parameters (client_secret_post), never both. Public clients only identify
// themselves with the client_id body parameter.
func (s *Server) AuthenticateClient(r *http.Request, form url.Values) (*identity.Client, *Error) {
	clientId, err := Param(form, "client_id")
	if err != nil {
		return nil, err
	}
	clientSecret, err := Param(form, "client_secret")
	if err != nil {
		return nil, err
	}

	usedBasic := false
	if header := r.Header.Get("Authorization"); header != "" {
		if !strings.HasPrefix(strings.ToLower(header), "basic ") {
			return nil, NewError(ErrorInvalidClient, "unsupported client authentication method")
		}
		basicId, basicSecret, ok := r.BasicAuth()
		if !ok {
			return nil, NewError(ErrorInvalidClient, "malformed basic authentication header")
		}
		// The client identifier and secret are form-urlencoded before they are base64 encoded (appendix B)
		id, err1 := url.QueryUnescape(basicId)
		secret, err2 := url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil {
			return nil, NewError(ErrorInvalidClient, "malformed basic authentication header")
		}
		if clientSecret != "" {
			return nil, NewError(ErrorInvalidRequest, "the client must not use more than one authentication method")
		}
		if clientId != "" && clientId != id {
			return nil, NewError(ErrorInvalidRequest, "the client_id parameter doesn't match the authenticated client")
		}
		clientId, clientSecret, usedBasic = id, secret, true
	}

	if clientId == "" {
		return nil, NewError(ErrorInvalidClient, "client authentication is required")
	}

	ctx := r.Context()
	client, lookupErr := s.opts.Store.GetClientByClientId(ctx, clientId)
	if lookupErr != nil && !errors.Is(lookupErr, store.ErrNotFound) {
		return nil, s.serverError(ctx, "failed to get client", lookupErr)
	}
	if client == nil || !client.Enabled {
		// Spend the time of a secret verification, so unknown clients can't be detected by timing
		if clientSecret != "" {
			s.opts.Hasher.Verify(s.dummySecret(), clientSecret)
		}
		return nil, NewError(ErrorInvalidClient, "client authentication failed")
	}

	if client.IsPublic() {
		if usedBasic || clientSecret != "" {
			return nil, NewError(ErrorInvalidClient, "public clients can't authenticate with a secret")
		}
		return client, nil
	}
	if clientSecret == "" || client.SecretHash == "" || s.opts.Hasher.Verify(client.SecretHash, clientSecret) != nil {
		return nil, NewError(ErrorInvalidClient, "client authentication failed")
	}
	return client, nil
}

func (s *Server) dummySecret() string {
	s.dummyOnce.Do(func() {
		s.dummyHash, _ = s.opts.Hasher.Hash(security.NewToken())
	})
	return s.dummyHash
}
