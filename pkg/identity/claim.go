package identity

import (
	"time"

	claimtypes "github.com/deb-ict/go-identity/pkg/identity/claim_types"
)

type Claims map[string]interface{}

func (c Claims) GetIssuer() string {
	return c[claimtypes.Issuer].(string)
}

func (c Claims) SetIssuer(value string) {
	c[claimtypes.Issuer] = value
}

func (c Claims) GetIssuedAt() time.Time {
	e := c[claimtypes.IssuedAt].(int64)
	return time.Unix(e, 0)
}

func (c Claims) SetIssuedAt(time time.Time) {
	c[claimtypes.IssuedAt] = time.Unix()
}

func (c Claims) GetExpiresAt() time.Time {
	e := c[claimtypes.ExpiresAt].(int64)
	return time.Unix(e, 0)
}

func (c Claims) SetExpiresAt(time time.Time) {
	c[claimtypes.ExpiresAt] = time.Unix()
}

func (c Claims) GetNotBefore() time.Time {
	e := c[claimtypes.NotBefore].(int64)
	return time.Unix(e, 0)
}

func (c Claims) SetNotBefore(time time.Time) {
	c[claimtypes.NotBefore] = time.Unix()
}

func (c Claims) GetAudience() string {
	return c[claimtypes.Audience].(string)
}

func (c Claims) SetAudience(value string) {
	c[claimtypes.Audience] = value
}

func (c Claims) GetSubject() string {
	return c[claimtypes.Subject].(string)
}

func (c Claims) SetSubject(value string) {
	c[claimtypes.Subject] = value
}
