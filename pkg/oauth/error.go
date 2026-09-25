package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Error codes of RFC 6749 section 4.1.2.1, 4.2.2.1 and 5.2, RFC 7009 section 2.2.1 and RFC 6750 section 3.1.
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorAccessDenied            = "access_denied"
	ErrorServerError             = "server_error"
	ErrorTemporarilyUnavailable  = "temporarily_unavailable"
	ErrorUnsupportedTokenType    = "unsupported_token_type"
	ErrorInvalidToken            = "invalid_token"
	ErrorInsufficientScope       = "insufficient_scope"
)

// Error is an OAuth 2.0 error response.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	// Status is the HTTP status code used when the error is returned directly (not by redirect).
	Status int `json:"-"`
}

// NewError creates an error with the default HTTP status for the error code.
func NewError(code string, description string) *Error {
	status := http.StatusBadRequest
	switch code {
	case ErrorInvalidClient, ErrorInvalidToken:
		status = http.StatusUnauthorized
	case ErrorInsufficientScope, ErrorAccessDenied:
		status = http.StatusForbidden
	case ErrorServerError:
		status = http.StatusInternalServerError
	case ErrorTemporarilyUnavailable:
		status = http.StatusServiceUnavailable
	}
	return &Error{Code: code, Description: description, Status: status}
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// AsError converts any error to an OAuth error. Errors that are not an *Error become a server_error.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return NewError(ErrorServerError, "the authorization server encountered an unexpected condition")
}

// WriteJSON writes a JSON response that must not be cached (RFC 6749 section 5.1).
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

// WriteError writes the error as a JSON response (RFC 6749 section 5.2).
func WriteError(w http.ResponseWriter, err *Error) {
	status := err.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	if err.Code == ErrorInvalidClient {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	WriteJSON(w, status, err)
}
