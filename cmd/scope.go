package main

import (
	"net/http"
	"strings"
)

type Scope struct {
}

func getRequestScopes(r *http.Request) ([]string, error) {
	scopeParam := r.Form["scope"]
	if len(scopeParam) == 0 {
		return []string{}, nil
	} else if len(scopeParam) > 1 {
		return []string{}, ErrInvalidRequest
	}
	return strings.Split(scopeParam[0], " "), nil
}
