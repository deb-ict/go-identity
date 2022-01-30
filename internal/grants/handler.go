package grants

import (
	"net/http"

	"github.com/deb-ict/go-identity/pkg/identity"
)

type GrantTypeHandler func(w http.ResponseWriter, r *http.Request, client *identity.Client)
