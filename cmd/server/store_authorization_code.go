package main

type AuthorizationCodeStore interface {
	GetAuthorizationCode(clientId string, code string) (*AuthorizationCode, error)
	CreateAuthorizationCode(code AuthorizationCode) error
	DeleteAuthorizationCode(code AuthorizationCode) error
}

type AuthorizationCode struct {
	ClientId    string
	Code        string
	RedirectUri string
}
