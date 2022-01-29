package response

import (
	"net/http"
)

type TokenResponse struct {
	AccessToken  string `json:"access_toke"`
	TokenType    string `json:"token_type"`
	Expires      int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	State        string `json:"state,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (r *TokenResponse) Write(w http.ResponseWriter) {
	JsonNoCache(w, r, http.StatusOK)
}
