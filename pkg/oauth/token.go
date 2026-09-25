package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

// TokenResponse is the successful token endpoint response (RFC 6749 section 5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenRequest is a token endpoint request of an authenticated client.
type TokenRequest struct {
	Client    *identity.Client
	GrantType identity.GrantType
	// Form contains the request body parameters.
	Form        url.Values
	HTTPRequest *http.Request
}

// GrantHandler processes the token request of a grant type. Return an *Error for OAuth errors.
type GrantHandler interface {
	HandleGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error)
}

// GrantHandlerFunc adapts a function to the GrantHandler interface.
type GrantHandlerFunc func(ctx context.Context, req *TokenRequest) (*TokenResponse, error)

func (f GrantHandlerFunc) HandleGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	return f(ctx, req)
}

// HandleToken is the token endpoint (RFC 6749 section 3.2).
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	response, err := s.token(w, r)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, response)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) (*TokenResponse, *Error) {
	form, err := parsePostForm(w, r)
	if err != nil {
		return nil, err
	}
	client, err := s.AuthenticateClient(r, form)
	if err != nil {
		return nil, err
	}
	grantType, err := RequiredParam(form, "grant_type")
	if err != nil {
		return nil, err
	}
	handler, ok := s.grants[identity.GrantType(grantType)]
	if !ok {
		return nil, NewError(ErrorUnsupportedGrantType, "the grant type is not supported")
	}
	if !client.ValidateGrantType(identity.GrantType(grantType)) {
		return nil, NewError(ErrorUnauthorizedClient, "the client is not authorized to use this grant type")
	}

	response, handlerErr := handler.HandleGrant(r.Context(), &TokenRequest{
		Client:      client,
		GrantType:   identity.GrantType(grantType),
		Form:        form,
		HTTPRequest: r,
	})
	if handlerErr != nil {
		var oauthErr *Error
		if errors.As(handlerErr, &oauthErr) {
			return nil, oauthErr
		}
		return nil, s.serverError(r.Context(), "token request failed", handlerErr)
	}
	return response, nil
}

// IssueOptions controls token issuance.
type IssueOptions struct {
	// RefreshToken issues a refresh token, when the client may use the refresh_token grant.
	RefreshToken bool
	// AuthorizationCodeId links the tokens to the authorization code they were issued for.
	AuthorizationCodeId string
}

// IssueTokens creates an access token, and optionally a refresh token, for the client and user.
// The user is nil when the client acts on its own behalf.
func (s *Server) IssueTokens(ctx context.Context, client *identity.Client, user *identity.User, scopes []string, opts IssueOptions) (*TokenResponse, error) {
	accessToken, value, err := s.createAccessToken(ctx, client, user, scopes, opts.AuthorizationCodeId)
	if err != nil {
		return nil, err
	}
	response := &TokenResponse{
		AccessToken: value,
		TokenType:   TokenTypeBearer,
		ExpiresIn:   int(accessToken.ExpiresAt.Sub(accessToken.CreatedAt).Seconds()),
		Scope:       identity.FormatScope(scopes),
	}
	if opts.RefreshToken && client.ValidateGrantType(identity.GrantTypeRefreshToken) {
		refreshToken, err := s.newRefreshToken(client, accessToken)
		if err != nil {
			return nil, err
		}
		response.RefreshToken, err = s.storeRefreshToken(ctx, refreshToken)
		if err != nil {
			return nil, err
		}
	}
	return response, nil
}

func (s *Server) createAccessToken(ctx context.Context, client *identity.Client, user *identity.User, scopes []string, codeId string) (*identity.AccessToken, string, error) {
	lifetime := client.AccessTokenLifetime
	if lifetime <= 0 {
		lifetime = identity.DefaultAccessTokenLifetime
	}
	now := s.now()
	token := &identity.AccessToken{
		Id:                  security.NewId(),
		ClientId:            client.Id,
		Scopes:              append([]string{}, scopes...),
		AuthorizationCodeId: codeId,
		CreatedAt:           now,
		ExpiresAt:           now.Add(lifetime),
	}
	if user != nil {
		token.UserId = user.Id
	}
	value, err := s.opts.TokenGenerator.GenerateAccessToken(ctx, token, client, user)
	if err != nil {
		return nil, "", err
	}
	token.TokenHash = security.HashToken(value)
	if err := s.opts.Store.CreateAccessToken(ctx, token); err != nil {
		return nil, "", err
	}
	return token, value, nil
}

func (s *Server) newRefreshToken(client *identity.Client, accessToken *identity.AccessToken) (*identity.RefreshToken, error) {
	lifetime := client.RefreshTokenLifetime
	if lifetime <= 0 {
		lifetime = identity.DefaultRefreshTokenLifetime
	}
	now := s.now()
	return &identity.RefreshToken{
		Id:                  security.NewId(),
		ClientId:            client.Id,
		UserId:              accessToken.UserId,
		AccessTokenId:       accessToken.Id,
		AuthorizationCodeId: accessToken.AuthorizationCodeId,
		Scopes:              append([]string{}, accessToken.Scopes...),
		TokenExpiration:     client.RefreshTokenExpiration,
		TokenUsage:          client.RefreshTokenUsage,
		Lifetime:            lifetime,
		CreatedAt:           now,
		UpdatedAt:           now,
		ExpiresAt:           now.Add(lifetime),
	}, nil
}

func (s *Server) storeRefreshToken(ctx context.Context, token *identity.RefreshToken) (string, error) {
	value := security.NewToken()
	token.TokenHash = security.HashToken(value)
	if err := s.opts.Store.CreateRefreshToken(ctx, token); err != nil {
		return "", err
	}
	return value, nil
}

// RevokeGrant deletes all tokens issued for an authorization code.
func (s *Server) RevokeGrant(ctx context.Context, authorizationCodeId string) error {
	filter := store.TokenFilter{AuthorizationCodeId: authorizationCodeId}
	if _, err := s.opts.Store.DeleteRefreshTokens(ctx, filter); err != nil {
		return err
	}
	_, err := s.opts.Store.DeleteAccessTokens(ctx, filter)
	return err
}

// lookupUser returns the user for a grant, or an invalid_grant error when the user can't sign in anymore.
func (s *Server) lookupUser(ctx context.Context, userId string) (*identity.User, error) {
	user, err := s.opts.Store.GetUserById(ctx, userId)
	if errors.Is(err, store.ErrNotFound) {
		return nil, NewError(ErrorInvalidGrant, "the resource owner doesn't exist")
	}
	if err != nil {
		return nil, err
	}
	if s.opts.Accounts.CanSignIn(user) != nil {
		return nil, NewError(ErrorInvalidGrant, "the resource owner account is not active")
	}
	return user, nil
}

// expiresAt returns the expiration time for a rotated refresh token: an absolute lifetime is
// kept, a sliding lifetime restarts.
func rotatedExpiresAt(old *identity.RefreshToken, now time.Time) time.Time {
	if old.TokenExpiration == identity.RefreshTokenExpirationAbsolute {
		return old.ExpiresAt
	}
	return now.Add(old.Lifetime)
}
