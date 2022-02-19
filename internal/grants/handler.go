package grants

import (
	"net/http"
	"strings"

	"github.com/deb-ict/go-identity/pkg/identity"
)

type GrantHandler interface {
	Handle(w http.ResponseWriter, r *http.Request, client *identity.Client)
}

type grantTypeBase struct {
}

func (base *grantTypeBase) GetRequestedScopes(r *http.Request, defaultScopes ...string) []string {
	s := r.FormValue("scope")
	if s == "" {
		return defaultScopes
	}
	return strings.Split(s, " ")
}

type GrantTypeHandler func(w http.ResponseWriter, r *http.Request, client *identity.Client)
