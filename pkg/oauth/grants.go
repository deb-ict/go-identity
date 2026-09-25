package oauth

import (
	"context"
	"errors"

	"github.com/deb-ict/go-identity/pkg/account"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

// authorizationCodeGrant exchanges an authorization code for tokens (RFC 6749 section 4.1.3, RFC 7636 section 4.5).
func (s *Server) authorizationCodeGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	codeValue, err := RequiredParam(req.Form, "code")
	if err != nil {
		return nil, err
	}
	redirectUri, err := Param(req.Form, "redirect_uri")
	if err != nil {
		return nil, err
	}
	codeVerifier, err := Param(req.Form, "code_verifier")
	if err != nil {
		return nil, err
	}

	code, lookupErr := s.opts.Store.GetAuthorizationCodeByHash(ctx, security.HashToken(codeValue))
	if errors.Is(lookupErr, store.ErrNotFound) {
		return nil, NewError(ErrorInvalidGrant, "the authorization code is invalid")
	}
	if lookupErr != nil {
		return nil, lookupErr
	}
	if code.ClientId != req.Client.Id {
		return nil, NewError(ErrorInvalidGrant, "the authorization code was issued to another client")
	}
	now := s.now()
	if code.IsConsumed() {
		// A code used twice might be stolen: revoke the tokens issued for it (section 4.1.2)
		if err := s.RevokeGrant(ctx, code.Id); err != nil {
			return nil, err
		}
		return nil, NewError(ErrorInvalidGrant, "the authorization code was already used")
	}
	if code.HasExpired(now) {
		return nil, NewError(ErrorInvalidGrant, "the authorization code has expired")
	}

	// The redirect_uri is required when it was included in the authorization request
	if code.RedirectUri != "" {
		if !code.ValidateRedirectUri(redirectUri) {
			return nil, NewError(ErrorInvalidGrant, "the redirect_uri doesn't match the authorization request")
		}
	} else if redirectUri != "" && !req.Client.ValidateRedirectUri(redirectUri) {
		return nil, NewError(ErrorInvalidGrant, "the redirect_uri doesn't match the authorization request")
	}

	// PKCE
	if code.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, NewError(ErrorInvalidGrant, "the code_verifier parameter is missing")
		}
		if !security.VerifyCodeChallenge(code.CodeChallenge, code.CodeChallengeMethod, codeVerifier) {
			return nil, NewError(ErrorInvalidGrant, "the code_verifier doesn't match the code_challenge")
		}
	} else if codeVerifier != "" {
		return nil, NewError(ErrorInvalidGrant, "the authorization request didn't include a code_challenge")
	}

	// Mark the code as used, atomically, so it can't be exchanged twice
	if consumeErr := s.opts.Store.ConsumeAuthorizationCode(ctx, code.Id, now); consumeErr != nil {
		if errors.Is(consumeErr, store.ErrConflict) {
			if err := s.RevokeGrant(ctx, code.Id); err != nil {
				return nil, err
			}
			return nil, NewError(ErrorInvalidGrant, "the authorization code was already used")
		}
		if errors.Is(consumeErr, store.ErrNotFound) {
			return nil, NewError(ErrorInvalidGrant, "the authorization code is invalid")
		}
		return nil, consumeErr
	}

	user, userErr := s.lookupUser(ctx, code.UserId)
	if userErr != nil {
		return nil, userErr
	}
	return s.IssueTokens(ctx, req.Client, user, code.Scopes, IssueOptions{RefreshToken: true, AuthorizationCodeId: code.Id})
}

// passwordGrant authenticates the resource owner with its credentials (RFC 6749 section 4.3.2).
func (s *Server) passwordGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	username, err := RequiredParam(req.Form, "username")
	if err != nil {
		return nil, err
	}
	password, err := RequiredParam(req.Form, "password")
	if err != nil {
		return nil, err
	}
	scope, err := Param(req.Form, "scope")
	if err != nil {
		return nil, err
	}
	scopes, err := resolveScopes(req.Client, scope)
	if err != nil {
		return nil, err
	}

	user, authErr := s.opts.Accounts.Authenticate(ctx, username, password)
	if authErr != nil {
		switch {
		case errors.Is(authErr, account.ErrInvalidCredentials):
			return nil, NewError(ErrorInvalidGrant, "invalid username or password")
		case errors.Is(authErr, account.ErrLockedOut):
			return nil, NewError(ErrorInvalidGrant, "the account is temporarily locked")
		case errors.Is(authErr, account.ErrDisabled), errors.Is(authErr, account.ErrNotActivated):
			return nil, NewError(ErrorInvalidGrant, "the account is not active")
		}
		return nil, authErr
	}
	return s.IssueTokens(ctx, req.Client, user, scopes, IssueOptions{RefreshToken: true})
}

// clientCredentialsGrant issues a token for the client itself (RFC 6749 section 4.4.2).
// A refresh token is not included (section 4.4.3).
func (s *Server) clientCredentialsGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	if req.Client.IsPublic() {
		return nil, NewError(ErrorUnauthorizedClient, "public clients can't use the client credentials grant")
	}
	scope, err := Param(req.Form, "scope")
	if err != nil {
		return nil, err
	}
	scopes, err := resolveScopes(req.Client, scope)
	if err != nil {
		return nil, err
	}
	return s.IssueTokens(ctx, req.Client, nil, scopes, IssueOptions{})
}

// refreshTokenGrant issues a new access token with a refresh token (RFC 6749 section 6).
func (s *Server) refreshTokenGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	value, err := RequiredParam(req.Form, "refresh_token")
	if err != nil {
		return nil, err
	}
	scope, err := Param(req.Form, "scope")
	if err != nil {
		return nil, err
	}

	refreshToken, lookupErr := s.opts.Store.GetRefreshTokenByHash(ctx, security.HashToken(value))
	if errors.Is(lookupErr, store.ErrNotFound) {
		return nil, NewError(ErrorInvalidGrant, "the refresh token is invalid")
	}
	if lookupErr != nil {
		return nil, lookupErr
	}
	if refreshToken.ClientId != req.Client.Id {
		return nil, NewError(ErrorInvalidGrant, "the refresh token was issued to another client")
	}
	now := s.now()
	if refreshToken.HasExpired(now) {
		return nil, NewError(ErrorInvalidGrant, "the refresh token has expired")
	}

	// The requested scope must not include any scope not originally granted, and is the
	// original scope when omitted.
	scopes := refreshToken.Scopes
	if scope != "" {
		scopes = identity.ParseScope(scope)
		if !identity.ValidateScopeSyntax(scopes) {
			return nil, NewError(ErrorInvalidScope, "the requested scope is malformed")
		}
		if !refreshToken.ValidateScopes(scopes) {
			return nil, NewError(ErrorInvalidScope, "the requested scope exceeds the scope granted by the resource owner")
		}
	}
	if !req.Client.ValidateScopes(scopes) {
		return nil, NewError(ErrorInvalidScope, "the requested scope is not allowed for this client")
	}

	var user *identity.User
	if refreshToken.UserId != "" {
		var userErr error
		user, userErr = s.lookupUser(ctx, refreshToken.UserId)
		if userErr != nil {
			return nil, userErr
		}
	}

	// The previous access token is replaced
	if refreshToken.AccessTokenId != "" {
		if err := s.opts.Store.DeleteAccessToken(ctx, refreshToken.AccessTokenId); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	accessToken, accessValue, createErr := s.createAccessToken(ctx, req.Client, user, scopes, refreshToken.AuthorizationCodeId)
	if createErr != nil {
		return nil, createErr
	}
	response := &TokenResponse{
		AccessToken: accessValue,
		TokenType:   TokenTypeBearer,
		ExpiresIn:   int(accessToken.ExpiresAt.Sub(accessToken.CreatedAt).Seconds()),
		Scope:       identity.FormatScope(scopes),
	}

	if refreshToken.TokenUsage == identity.RefreshTokenUsageOneTime {
		// Rotate: the new refresh token keeps the original scope
		if err := s.opts.Store.DeleteRefreshToken(ctx, refreshToken.Id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Used concurrently by another request
				s.opts.Store.DeleteAccessToken(ctx, accessToken.Id)
				return nil, NewError(ErrorInvalidGrant, "the refresh token is invalid")
			}
			return nil, err
		}
		rotated := &identity.RefreshToken{
			Id:                  security.NewId(),
			ClientId:            refreshToken.ClientId,
			UserId:              refreshToken.UserId,
			AccessTokenId:       accessToken.Id,
			AuthorizationCodeId: refreshToken.AuthorizationCodeId,
			Scopes:              refreshToken.Scopes,
			TokenExpiration:     refreshToken.TokenExpiration,
			TokenUsage:          refreshToken.TokenUsage,
			Lifetime:            refreshToken.Lifetime,
			CreatedAt:           now,
			UpdatedAt:           now,
			ExpiresAt:           rotatedExpiresAt(refreshToken, now),
		}
		rotatedValue, storeErr := s.storeRefreshToken(ctx, rotated)
		if storeErr != nil {
			return nil, storeErr
		}
		response.RefreshToken = rotatedValue
	} else {
		// Reuse: the client keeps its refresh token, so it isn't included in the response
		refreshToken.AccessTokenId = accessToken.Id
		refreshToken.Touch(now)
		if err := s.opts.Store.UpdateRefreshToken(ctx, refreshToken); err != nil {
			return nil, err
		}
	}
	return response, nil
}
