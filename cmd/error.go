package main

import "errors"

var (
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrInvalidClient           = errors.New("invalid_client")
	ErrInvalidGrant            = errors.New("invalid_grant")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrUnsupportedGrantType    = errors.New("invalid_grant")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrAccessDenied            = errors.New("access_denied")
	ErrServerError             = errors.New("server_error")
	ErrTemporarilyUnavailable  = errors.New("temporarily_unavailable")
)
