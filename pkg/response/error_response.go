package response

import (
	"net/http"
)

// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
const (
	errAccessDenied            string = "access_denied"
	errInvalidRequest          string = "invalid_request"
	errInvalidGrant            string = "invalid_grant"
	errInvalidClient           string = "invalid_client"
	errInvalidScope            string = "invalid_scope"
	errUnauthorizedClient      string = "unauthorized_client"
	errUnsupportedGrantType    string = "unsupported_grant_type"
	errUnsupportedResponseType string = "unsupported_response_type"
)

type ErrorReponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
	Uri         string `json:"error_uri,omitempty"`
}

func AccessDenied(w http.ResponseWriter) {
	JsonNoCache(w, &ErrorReponse{
		Error: errAccessDenied,
	}, http.StatusBadRequest)
}

func InvalidRequest(w http.ResponseWriter) {
	JsonNoCache(w, &ErrorReponse{
		Error: errInvalidRequest,
	}, http.StatusBadRequest)
}

func InvalidClient(w http.ResponseWriter) {
	JsonNoCache(w, &ErrorReponse{
		Error: errInvalidClient,
	}, http.StatusBadRequest)
}

func InvalidClientAuth(w http.ResponseWriter) {
	//TODO: include the "WWW-Authenticate" response header field
	//      matching the authentication scheme used by the client.
	JsonNoCache(w, &ErrorReponse{
		Error: errInvalidClient,
	}, http.StatusUnauthorized)
}

func InvalidGrant(w http.ResponseWriter) {
	JsonNoCache(w, &ErrorReponse{
		Error: errInvalidGrant,
	}, http.StatusBadRequest)
}

func InvalidScope(w http.ResponseWriter) {
	JsonNoCache(w, &ErrorReponse{
		Error: errInvalidScope,
	}, http.StatusBadRequest)
}

func UnauthorizedClient(w http.ResponseWriter) {
	JsonNoCache(w, &ErrorReponse{
		Error: errUnauthorizedClient,
	}, http.StatusBadRequest)
}

func UnsupportedGrantType(w http.ResponseWriter) {
	JsonNoCache(w, &ErrorReponse{
		Error: errUnsupportedGrantType,
	}, http.StatusBadRequest)
}

func UnsupportedResponseType(w http.ResponseWriter) {
	JsonNoCache(w, &ErrorReponse{
		Error: errUnsupportedResponseType,
	}, http.StatusBadRequest)
}
