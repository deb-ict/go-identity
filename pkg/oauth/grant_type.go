package oauth

import (
	"errors"
	"net/http"
	"strings"
)

type GrantTypeHandler interface {
	HandleRequest(client *Client, r *http.Request) (*AccessToken, *RefreshToken, error)
}

func getValidatedScopes(client *Client, r *http.Request) ([]string, error) {
	scopes, err := getScopesParam(r)
	if err != nil {
		return []string{}, err
	}
	if len(scopes) > 0 {
		return scopes, nil
	}
	return client.AllowedScopes, nil
}

func getScopesParam(r *http.Request) ([]string, error) {
	scopeParam := r.Form["scope"]
	if len(scopeParam) > 1 {
		return []string{}, errors.New("invalid_request")
	} else if len(scopeParam) == 1 {
		return strings.Split(scopeParam[0], " "), nil
	}
	return []string{}, nil
}

func getStringParam(r *http.Request, name string) (string, error) {
	value := r.Form[name]
	if len(value) != 1 {
		return "", errors.New("invalid_request")
	}
	return value[0], nil
}
