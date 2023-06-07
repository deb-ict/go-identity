package oauth

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
	HelpUri     string `json:"error_uri,omitempty"`
}
