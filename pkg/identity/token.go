package identity

import (
	"time"
)

// UserTokenPurpose identifies what a one-time user token can be used for.
type UserTokenPurpose string

const (
	UserTokenPurposeActivation    UserTokenPurpose = "activation"
	UserTokenPurposePasswordReset UserTokenPurpose = "password_reset"
)

// AccessToken is an issued access token (RFC 6749 section 1.4).
// Only the hash of the token value is persisted.
type AccessToken struct {
	Id                  string
	TokenHash           string
	ClientId            string
	UserId              string
	Scopes              []string
	AuthorizationCodeId string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

func (token *AccessToken) HasExpired(now time.Time) bool {
	return !now.Before(token.ExpiresAt)
}

// RefreshToken is an issued refresh token (RFC 6749 section 1.5).
// Only the hash of the token value is persisted.
type RefreshToken struct {
	Id                  string
	TokenHash           string
	ClientId            string
	UserId              string
	AccessTokenId       string
	AuthorizationCodeId string
	Scopes              []string
	TokenExpiration     RefreshTokenExpirationType
	TokenUsage          RefreshTokenUsage
	Lifetime            time.Duration
	CreatedAt           time.Time
	UpdatedAt           time.Time
	ExpiresAt           time.Time
}

func (token *RefreshToken) HasExpired(now time.Time) bool {
	return !now.Before(token.ExpiresAt)
}

// Touch updates the refresh token after it has been used.
func (token *RefreshToken) Touch(now time.Time) {
	token.UpdatedAt = now
	if token.TokenExpiration == RefreshTokenExpirationSliding {
		token.ExpiresAt = now.Add(token.Lifetime)
	}
}

func (token *RefreshToken) ValidateScope(scope string) bool {
	for _, allowedScope := range token.Scopes {
		if allowedScope == scope {
			return true
		}
	}
	return false
}

func (token *RefreshToken) ValidateScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !token.ValidateScope(scope) {
			return false
		}
	}
	return true
}

// AuthorizationCode is an issued authorization code (RFC 6749 section 4.1.2).
// Only the hash of the code is persisted.
type AuthorizationCode struct {
	Id                  string
	CodeHash            string
	ClientId            string
	UserId              string
	Scopes              []string
	RedirectUri         string
	CodeChallenge       string
	CodeChallengeMethod string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
}

func (code *AuthorizationCode) HasExpired(now time.Time) bool {
	return !now.Before(code.ExpiresAt)
}

func (code *AuthorizationCode) IsConsumed() bool {
	return code.ConsumedAt != nil
}

// ValidateRedirectUri checks the redirect_uri of the token request (RFC 6749 section 4.1.3).
// When the authorization request included a redirect_uri, the values must be identical.
func (code *AuthorizationCode) ValidateRedirectUri(redirectUri string) bool {
	return redirectUri == code.RedirectUri
}

// UserToken is a one-time token sent to a user, e.g. to activate the account or reset the password.
// Only the hash of the token value is persisted.
type UserToken struct {
	Id        string
	UserId    string
	Purpose   UserTokenPurpose
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (token *UserToken) HasExpired(now time.Time) bool {
	return !now.Before(token.ExpiresAt)
}
