package http

import (
	"errors"
	"net/http"
	"strings"
)

func GetScopesParam(r *http.Request) ([]string, error) {
	if r.Form == nil {
		err := r.ParseForm()
		if err != nil {
			return []string{}, errors.New("invalid_request")
		}
	}

	scopeParam := r.Form["scope"]
	if len(scopeParam) > 1 {
		return []string{}, errors.New("invalid_request")
	} else if len(scopeParam) == 1 {
		return strings.Split(scopeParam[0], " "), nil
	}
	return []string{}, nil
}

func GetStringParam(r *http.Request, name string) (string, error) {
	if r.Form == nil {
		err := r.ParseForm()
		if err != nil {
			return "", errors.New("invalid_request")
		}
	}

	value := r.Form[name]
	if len(value) != 1 {
		return "", errors.New("invalid_request")
	}
	return value[0], nil
}
