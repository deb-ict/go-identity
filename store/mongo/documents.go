package mongostore

import (
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
)

// The BSON documents are private so the identity models stay free of storage concerns.
// Durations are stored as int64 nanoseconds, times as BSON datetimes (millisecond precision, UTC).

type clientDocument struct {
	Id                        string    `bson:"_id"`
	ClientId                  string    `bson:"client_id"`
	Name                      string    `bson:"name"`
	Description               string    `bson:"description"`
	Type                      string    `bson:"type"`
	SecretHash                string    `bson:"secret_hash"`
	RedirectUris              []string  `bson:"redirect_uris"`
	AllowedScopes             []string  `bson:"allowed_scopes"`
	DefaultScopes             []string  `bson:"default_scopes"`
	AllowedGrantTypes         []string  `bson:"allowed_grant_types"`
	RequireConsent            bool      `bson:"require_consent"`
	RequirePkce               bool      `bson:"require_pkce"`
	Enabled                   bool      `bson:"enabled"`
	AccessTokenLifetime       int64     `bson:"access_token_lifetime"`
	AuthorizationCodeLifetime int64     `bson:"authorization_code_lifetime"`
	RefreshTokenUsage         string    `bson:"refresh_token_usage"`
	RefreshTokenExpiration    string    `bson:"refresh_token_expiration"`
	RefreshTokenLifetime      int64     `bson:"refresh_token_lifetime"`
	CreatedAt                 time.Time `bson:"created_at"`
	UpdatedAt                 time.Time `bson:"updated_at"`
}

type userDocument struct {
	Id                 string     `bson:"_id"`
	Username           string     `bson:"username"`
	NormalizedUsername string     `bson:"normalized_username"`
	Email              string     `bson:"email"`
	NormalizedEmail    string     `bson:"normalized_email"`
	PasswordHash       string     `bson:"password_hash"`
	EmailVerified      bool       `bson:"email_verified"`
	Enabled            bool       `bson:"enabled"`
	SecurityStamp      string     `bson:"security_stamp"`
	FailedLoginCount   int64      `bson:"failed_login_count"`
	LockoutEnd         *time.Time `bson:"lockout_end"`
	LastLoginAt        *time.Time `bson:"last_login_at"`
	CreatedAt          time.Time  `bson:"created_at"`
	UpdatedAt          time.Time  `bson:"updated_at"`
}

type accessTokenDocument struct {
	Id                  string    `bson:"_id"`
	TokenHash           string    `bson:"token_hash"`
	ClientId            string    `bson:"client_id"`
	UserId              string    `bson:"user_id"`
	Scopes              []string  `bson:"scopes"`
	AuthorizationCodeId string    `bson:"authorization_code_id"`
	CreatedAt           time.Time `bson:"created_at"`
	ExpiresAt           time.Time `bson:"expires_at"`
}

type refreshTokenDocument struct {
	Id                  string    `bson:"_id"`
	TokenHash           string    `bson:"token_hash"`
	ClientId            string    `bson:"client_id"`
	UserId              string    `bson:"user_id"`
	AccessTokenId       string    `bson:"access_token_id"`
	AuthorizationCodeId string    `bson:"authorization_code_id"`
	Scopes              []string  `bson:"scopes"`
	TokenExpiration     string    `bson:"token_expiration"`
	TokenUsage          string    `bson:"token_usage"`
	Lifetime            int64     `bson:"lifetime"`
	CreatedAt           time.Time `bson:"created_at"`
	UpdatedAt           time.Time `bson:"updated_at"`
	ExpiresAt           time.Time `bson:"expires_at"`
}

type authorizationCodeDocument struct {
	Id                  string     `bson:"_id"`
	CodeHash            string     `bson:"code_hash"`
	ClientId            string     `bson:"client_id"`
	UserId              string     `bson:"user_id"`
	Scopes              []string   `bson:"scopes"`
	RedirectUri         string     `bson:"redirect_uri"`
	CodeChallenge       string     `bson:"code_challenge"`
	CodeChallengeMethod string     `bson:"code_challenge_method"`
	CreatedAt           time.Time  `bson:"created_at"`
	ExpiresAt           time.Time  `bson:"expires_at"`
	ConsumedAt          *time.Time `bson:"consumed_at"`
}

type userTokenDocument struct {
	Id        string    `bson:"_id"`
	UserId    string    `bson:"user_id"`
	Purpose   string    `bson:"purpose"`
	TokenHash string    `bson:"token_hash"`
	CreatedAt time.Time `bson:"created_at"`
	ExpiresAt time.Time `bson:"expires_at"`
}

// Helpers

// toDBTime truncates to the millisecond precision of a BSON datetime and converts to UTC.
func toDBTime(t time.Time) time.Time {
	return t.Truncate(time.Millisecond).UTC()
}

func toDBTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := toDBTime(*t)
	return &v
}

func fromDBTime(t time.Time) time.Time {
	return t.UTC()
}

func fromDBTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

// copyStrings copies the slice; nil becomes an empty slice so documents never contain null arrays.
func copyStrings(s []string) []string {
	return append([]string{}, s...)
}

func grantTypesToStrings(g []identity.GrantType) []string {
	result := make([]string, 0, len(g))
	for _, v := range g {
		result = append(result, string(v))
	}
	return result
}

func stringsToGrantTypes(s []string) []identity.GrantType {
	result := make([]identity.GrantType, 0, len(s))
	for _, v := range s {
		result = append(result, identity.GrantType(v))
	}
	return result
}

// Clients

func clientToDocument(c *identity.Client) *clientDocument {
	return &clientDocument{
		Id:                        c.Id,
		ClientId:                  c.ClientId,
		Name:                      c.Name,
		Description:               c.Description,
		Type:                      string(c.Type),
		SecretHash:                c.SecretHash,
		RedirectUris:              copyStrings(c.RedirectUris),
		AllowedScopes:             copyStrings(c.AllowedScopes),
		DefaultScopes:             copyStrings(c.DefaultScopes),
		AllowedGrantTypes:         grantTypesToStrings(c.AllowedGrantTypes),
		RequireConsent:            c.RequireConsent,
		RequirePkce:               c.RequirePkce,
		Enabled:                   c.Enabled,
		AccessTokenLifetime:       int64(c.AccessTokenLifetime),
		AuthorizationCodeLifetime: int64(c.AuthorizationCodeLifetime),
		RefreshTokenUsage:         string(c.RefreshTokenUsage),
		RefreshTokenExpiration:    string(c.RefreshTokenExpiration),
		RefreshTokenLifetime:      int64(c.RefreshTokenLifetime),
		CreatedAt:                 toDBTime(c.CreatedAt),
		UpdatedAt:                 toDBTime(c.UpdatedAt),
	}
}

func (d *clientDocument) toModel() *identity.Client {
	return &identity.Client{
		Id:                        d.Id,
		ClientId:                  d.ClientId,
		Name:                      d.Name,
		Description:               d.Description,
		Type:                      identity.ClientType(d.Type),
		SecretHash:                d.SecretHash,
		RedirectUris:              copyStrings(d.RedirectUris),
		AllowedScopes:             copyStrings(d.AllowedScopes),
		DefaultScopes:             copyStrings(d.DefaultScopes),
		AllowedGrantTypes:         stringsToGrantTypes(d.AllowedGrantTypes),
		RequireConsent:            d.RequireConsent,
		RequirePkce:               d.RequirePkce,
		Enabled:                   d.Enabled,
		AccessTokenLifetime:       time.Duration(d.AccessTokenLifetime),
		AuthorizationCodeLifetime: time.Duration(d.AuthorizationCodeLifetime),
		RefreshTokenUsage:         identity.RefreshTokenUsage(d.RefreshTokenUsage),
		RefreshTokenExpiration:    identity.RefreshTokenExpirationType(d.RefreshTokenExpiration),
		RefreshTokenLifetime:      time.Duration(d.RefreshTokenLifetime),
		CreatedAt:                 fromDBTime(d.CreatedAt),
		UpdatedAt:                 fromDBTime(d.UpdatedAt),
	}
}

// Users

func userToDocument(u *identity.User) *userDocument {
	return &userDocument{
		Id:                 u.Id,
		Username:           u.Username,
		NormalizedUsername: u.NormalizedUsername,
		Email:              u.Email,
		NormalizedEmail:    u.NormalizedEmail,
		PasswordHash:       u.PasswordHash,
		EmailVerified:      u.EmailVerified,
		Enabled:            u.Enabled,
		SecurityStamp:      u.SecurityStamp,
		FailedLoginCount:   int64(u.FailedLoginCount),
		LockoutEnd:         toDBTimePtr(u.LockoutEnd),
		LastLoginAt:        toDBTimePtr(u.LastLoginAt),
		CreatedAt:          toDBTime(u.CreatedAt),
		UpdatedAt:          toDBTime(u.UpdatedAt),
	}
}

func (d *userDocument) toModel() *identity.User {
	return &identity.User{
		Id:                 d.Id,
		Username:           d.Username,
		NormalizedUsername: d.NormalizedUsername,
		Email:              d.Email,
		NormalizedEmail:    d.NormalizedEmail,
		PasswordHash:       d.PasswordHash,
		EmailVerified:      d.EmailVerified,
		Enabled:            d.Enabled,
		SecurityStamp:      d.SecurityStamp,
		FailedLoginCount:   int(d.FailedLoginCount),
		LockoutEnd:         fromDBTimePtr(d.LockoutEnd),
		LastLoginAt:        fromDBTimePtr(d.LastLoginAt),
		CreatedAt:          fromDBTime(d.CreatedAt),
		UpdatedAt:          fromDBTime(d.UpdatedAt),
	}
}

// Access tokens

func accessTokenToDocument(t *identity.AccessToken) *accessTokenDocument {
	return &accessTokenDocument{
		Id:                  t.Id,
		TokenHash:           t.TokenHash,
		ClientId:            t.ClientId,
		UserId:              t.UserId,
		Scopes:              copyStrings(t.Scopes),
		AuthorizationCodeId: t.AuthorizationCodeId,
		CreatedAt:           toDBTime(t.CreatedAt),
		ExpiresAt:           toDBTime(t.ExpiresAt),
	}
}

func (d *accessTokenDocument) toModel() *identity.AccessToken {
	return &identity.AccessToken{
		Id:                  d.Id,
		TokenHash:           d.TokenHash,
		ClientId:            d.ClientId,
		UserId:              d.UserId,
		Scopes:              copyStrings(d.Scopes),
		AuthorizationCodeId: d.AuthorizationCodeId,
		CreatedAt:           fromDBTime(d.CreatedAt),
		ExpiresAt:           fromDBTime(d.ExpiresAt),
	}
}

// Refresh tokens

func refreshTokenToDocument(t *identity.RefreshToken) *refreshTokenDocument {
	return &refreshTokenDocument{
		Id:                  t.Id,
		TokenHash:           t.TokenHash,
		ClientId:            t.ClientId,
		UserId:              t.UserId,
		AccessTokenId:       t.AccessTokenId,
		AuthorizationCodeId: t.AuthorizationCodeId,
		Scopes:              copyStrings(t.Scopes),
		TokenExpiration:     string(t.TokenExpiration),
		TokenUsage:          string(t.TokenUsage),
		Lifetime:            int64(t.Lifetime),
		CreatedAt:           toDBTime(t.CreatedAt),
		UpdatedAt:           toDBTime(t.UpdatedAt),
		ExpiresAt:           toDBTime(t.ExpiresAt),
	}
}

func (d *refreshTokenDocument) toModel() *identity.RefreshToken {
	return &identity.RefreshToken{
		Id:                  d.Id,
		TokenHash:           d.TokenHash,
		ClientId:            d.ClientId,
		UserId:              d.UserId,
		AccessTokenId:       d.AccessTokenId,
		AuthorizationCodeId: d.AuthorizationCodeId,
		Scopes:              copyStrings(d.Scopes),
		TokenExpiration:     identity.RefreshTokenExpirationType(d.TokenExpiration),
		TokenUsage:          identity.RefreshTokenUsage(d.TokenUsage),
		Lifetime:            time.Duration(d.Lifetime),
		CreatedAt:           fromDBTime(d.CreatedAt),
		UpdatedAt:           fromDBTime(d.UpdatedAt),
		ExpiresAt:           fromDBTime(d.ExpiresAt),
	}
}

// Authorization codes

func authorizationCodeToDocument(c *identity.AuthorizationCode) *authorizationCodeDocument {
	return &authorizationCodeDocument{
		Id:                  c.Id,
		CodeHash:            c.CodeHash,
		ClientId:            c.ClientId,
		UserId:              c.UserId,
		Scopes:              copyStrings(c.Scopes),
		RedirectUri:         c.RedirectUri,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		CreatedAt:           toDBTime(c.CreatedAt),
		ExpiresAt:           toDBTime(c.ExpiresAt),
		ConsumedAt:          toDBTimePtr(c.ConsumedAt),
	}
}

func (d *authorizationCodeDocument) toModel() *identity.AuthorizationCode {
	return &identity.AuthorizationCode{
		Id:                  d.Id,
		CodeHash:            d.CodeHash,
		ClientId:            d.ClientId,
		UserId:              d.UserId,
		Scopes:              copyStrings(d.Scopes),
		RedirectUri:         d.RedirectUri,
		CodeChallenge:       d.CodeChallenge,
		CodeChallengeMethod: d.CodeChallengeMethod,
		CreatedAt:           fromDBTime(d.CreatedAt),
		ExpiresAt:           fromDBTime(d.ExpiresAt),
		ConsumedAt:          fromDBTimePtr(d.ConsumedAt),
	}
}

// User tokens

func userTokenToDocument(t *identity.UserToken) *userTokenDocument {
	return &userTokenDocument{
		Id:        t.Id,
		UserId:    t.UserId,
		Purpose:   string(t.Purpose),
		TokenHash: t.TokenHash,
		CreatedAt: toDBTime(t.CreatedAt),
		ExpiresAt: toDBTime(t.ExpiresAt),
	}
}

func (d *userTokenDocument) toModel() *identity.UserToken {
	return &identity.UserToken{
		Id:        d.Id,
		UserId:    d.UserId,
		Purpose:   identity.UserTokenPurpose(d.Purpose),
		TokenHash: d.TokenHash,
		CreatedAt: fromDBTime(d.CreatedAt),
		ExpiresAt: fromDBTime(d.ExpiresAt),
	}
}
