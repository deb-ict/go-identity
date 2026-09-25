package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/session"
	"github.com/deb-ict/go-identity/pkg/store"
)

// Consent decision parameter posted by the consent page.
const (
	ParamConsent = "consent"
	ConsentAllow = "allow"
	ConsentDeny  = "deny"
)

// authorizeRequest is a validated authorization request.
type authorizeRequest struct {
	client *identity.Client
	// redirectUri is where the response is sent; redirectUriParam is the value of the
	// redirect_uri parameter, empty when omitted.
	redirectUri         string
	redirectUriParam    string
	responseType        identity.ResponseType
	state               string
	scopes              []string
	codeChallenge       string
	codeChallengeMethod string
}

// HandleAuthorize is the authorization endpoint (RFC 6749 section 3.1). It supports GET and POST.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	interaction := s.opts.Interaction
	w.Header().Set("Cache-Control", "no-store")

	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseForm(); err != nil {
		interaction.Error(w, r, NewError(ErrorInvalidRequest, "the request is malformed"))
		return
	}
	params := r.Form

	// Errors in the client identifier or redirection URI are shown to the user, the user agent
	// must not be redirected to an unverified URI (section 4.1.2.1).
	req, pageErr := s.validateClientAndRedirect(r, params)
	if pageErr != nil {
		interaction.Error(w, r, pageErr)
		return
	}

	// Other errors are returned to the client by redirect
	if err := s.validateAuthorizeRequest(req, params); err != nil {
		s.redirectError(w, r, req, err)
		return
	}

	// Authenticate the resource owner
	user, userErr := interaction.CurrentUser(w, r)
	if userErr != nil {
		s.redirectError(w, r, req, s.serverError(ctx, "failed to get the current user", userErr))
		return
	}
	if user == nil {
		interaction.Login(w, r, s.authorizeURL(params))
		return
	}
	if s.opts.Accounts.CanSignIn(user) != nil {
		s.redirectError(w, r, req, NewError(ErrorAccessDenied, "the resource owner account is not active"))
		return
	}

	// Obtain the authorization decision of the resource owner
	if req.client.RequireConsent {
		decision := ""
		if r.Method == http.MethodPost {
			decision = r.PostForm.Get(ParamConsent)
		}
		if decision == "" {
			interaction.Consent(w, r, &ConsentRequest{
				Client: req.client,
				User:   user,
				Scopes: req.scopes,
				Action: s.opts.BasePath + PathAuthorize,
				Params: authorizeParams(params),
			})
			return
		}
		if !interaction.VerifyConsent(r) {
			interaction.Error(w, r, NewError(ErrorInvalidRequest, "the consent form has expired, please try again"))
			return
		}
		if decision != ConsentAllow {
			s.redirectError(w, r, req, NewError(ErrorAccessDenied, "the resource owner denied the request"))
			return
		}
	}

	switch req.responseType {
	case identity.ResponseTypeCode:
		s.issueCode(w, r, req, user)
	case identity.ResponseTypeToken:
		s.issueImplicitToken(w, r, req, user)
	}
}

func (s *Server) validateClientAndRedirect(r *http.Request, params url.Values) (*authorizeRequest, *Error) {
	clientId, err := RequiredParam(params, "client_id")
	if err != nil {
		return nil, err
	}
	client, lookupErr := s.opts.Store.GetClientByClientId(r.Context(), clientId)
	if errors.Is(lookupErr, store.ErrNotFound) || lookupErr == nil && !client.Enabled {
		return nil, NewError(ErrorInvalidClient, "the client is unknown")
	}
	if lookupErr != nil {
		return nil, s.serverError(r.Context(), "failed to get client", lookupErr)
	}

	redirectUri, err := Param(params, "redirect_uri")
	if err != nil {
		return nil, err
	}
	// The response is only ever sent to a registered redirection URI
	req := &authorizeRequest{client: client, redirectUriParam: redirectUri}
	if redirectUri == "" {
		// Without redirect_uri, the client must have exactly one registered URI (section 3.1.2.3)
		if len(client.RedirectUris) != 1 {
			return nil, NewError(ErrorInvalidRequest, "the redirect_uri parameter is missing")
		}
		req.redirectUri = client.RedirectUris[0]
	} else if registered, ok := client.MatchRedirectUri(redirectUri); ok {
		req.redirectUri = registered
	} else {
		return nil, NewError(ErrorInvalidRequest, "the redirect_uri is not registered for this client")
	}
	return req, nil
}

func (s *Server) validateAuthorizeRequest(req *authorizeRequest, params url.Values) *Error {
	state, err := Param(params, "state")
	if err != nil {
		return err
	}
	req.state = state

	responseType, err := Param(params, "response_type")
	if err != nil {
		return err
	}
	req.responseType = identity.ResponseType(responseType)
	switch req.responseType {
	case "":
		return NewError(ErrorInvalidRequest, "the response_type parameter is missing")
	case identity.ResponseTypeCode:
		if !req.client.ValidateGrantType(identity.GrantTypeAuthorizationCode) {
			return NewError(ErrorUnauthorizedClient, "the client is not authorized to use the authorization code grant")
		}
	case identity.ResponseTypeToken:
		if !req.client.ValidateGrantType(identity.GrantTypeImplicit) {
			return NewError(ErrorUnauthorizedClient, "the client is not authorized to use the implicit grant")
		}
	default:
		return NewError(ErrorUnsupportedResponseType, "the response_type is not supported")
	}

	scope, err := Param(params, "scope")
	if err != nil {
		return err
	}
	req.scopes, err = resolveScopes(req.client, scope)
	if err != nil {
		return err
	}

	if req.responseType == identity.ResponseTypeCode {
		challenge, err := Param(params, "code_challenge")
		if err != nil {
			return err
		}
		method, err := Param(params, "code_challenge_method")
		if err != nil {
			return err
		}
		if challenge == "" {
			if req.client.RequirePkce || req.client.IsPublic() {
				return NewError(ErrorInvalidRequest, "the code_challenge parameter is required")
			}
		} else {
			if method == "" {
				method = security.CodeChallengeMethodPlain
			}
			if !security.IsSupportedCodeChallengeMethod(method) {
				return NewError(ErrorInvalidRequest, "the code_challenge_method is not supported")
			}
			if !security.IsValidCodeVerifier(challenge) {
				return NewError(ErrorInvalidRequest, "the code_challenge is malformed")
			}
			req.codeChallenge = challenge
			req.codeChallengeMethod = method
		}
	}
	return nil
}

func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, req *authorizeRequest, user *identity.User) {
	ctx := r.Context()
	lifetime := req.client.AuthorizationCodeLifetime
	if lifetime <= 0 {
		lifetime = identity.DefaultAuthorizationCodeLifetime
	}
	now := s.now()
	value := security.NewToken()
	code := &identity.AuthorizationCode{
		Id:                  security.NewId(),
		CodeHash:            security.HashToken(value),
		ClientId:            req.client.Id,
		UserId:              user.Id,
		Scopes:              req.scopes,
		RedirectUri:         req.redirectUriParam,
		CodeChallenge:       req.codeChallenge,
		CodeChallengeMethod: req.codeChallengeMethod,
		CreatedAt:           now,
		ExpiresAt:           now.Add(lifetime),
	}
	if err := s.opts.Store.CreateAuthorizationCode(ctx, code); err != nil {
		s.redirectError(w, r, req, s.serverError(ctx, "failed to create authorization code", err))
		return
	}
	values := url.Values{"code": {value}}
	if req.state != "" {
		values.Set("state", req.state)
	}
	redirect(w, r, req.redirectUri, values, false)
}

func (s *Server) issueImplicitToken(w http.ResponseWriter, r *http.Request, req *authorizeRequest, user *identity.User) {
	ctx := r.Context()
	// The implicit grant never issues a refresh token (section 4.2.2)
	response, err := s.IssueTokens(ctx, req.client, user, req.scopes, IssueOptions{})
	if err != nil {
		s.redirectError(w, r, req, s.serverError(ctx, "failed to issue access token", err))
		return
	}
	values := url.Values{
		"access_token": {response.AccessToken},
		"token_type":   {response.TokenType},
		"expires_in":   {strconv.Itoa(response.ExpiresIn)},
	}
	if response.Scope != "" {
		values.Set("scope", response.Scope)
	}
	if req.state != "" {
		values.Set("state", req.state)
	}
	redirect(w, r, req.redirectUri, values, true)
}

// redirectError sends the error to the client redirection URI (section 4.1.2.1 and 4.2.2.1).
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, req *authorizeRequest, err *Error) {
	values := url.Values{"error": {err.Code}}
	if err.Description != "" {
		values.Set("error_description", err.Description)
	}
	if err.URI != "" {
		values.Set("error_uri", err.URI)
	}
	if req.state != "" {
		values.Set("state", req.state)
	}
	redirect(w, r, req.redirectUri, values, req.responseType == identity.ResponseTypeToken)
}

// redirect adds the parameters to the query or fragment of the redirection URI. The query
// component of a registered redirection URI is retained (section 3.1.2).
func redirect(w http.ResponseWriter, r *http.Request, redirectUri string, values url.Values, fragment bool) {
	target := redirectUri
	if fragment {
		target += "#" + values.Encode()
	} else if strings.Contains(redirectUri, "?") {
		target += "&" + values.Encode()
	} else {
		target += "?" + values.Encode()
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

// authorizeParams returns the authorization request parameters without the consent form fields.
func authorizeParams(params url.Values) url.Values {
	result := url.Values{}
	for k, v := range params {
		if k == ParamConsent || k == session.CSRFFieldName {
			continue
		}
		result[k] = append([]string{}, v...)
	}
	return result
}

// authorizeURL is the local URL to resume the authorization request after login.
func (s *Server) authorizeURL(params url.Values) string {
	return s.opts.BasePath + PathAuthorize + "?" + authorizeParams(params).Encode()
}
