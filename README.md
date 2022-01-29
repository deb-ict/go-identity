# go-identity
Multi tenant identity server (OIDC/OAuth2.0)


# TODO
- Implement rate limit.
- Support basic auth headers

```
file: pkg/response/error_response.go

func InvalidClientAuth(w http.ResponseWriter) error {
	//TODO: include the "WWW-Authenticate" response header field
	//      matching the authentication scheme used by the client.
	err := ErrInvalidClient
	JsonNoCache(w, &ErrorReponse{
		Error: err.Error(),
	}, http.StatusUnauthorized)
	return err
}
```
