package wip

import (
	"encoding/json"
	"net/http"
)

//https://openid.net/specs/openid-connect-discovery-1_0.html
type openIdConfig struct {
	Issuer                 string   `json:"issuer"`
	JwksUri                string   `json:"jwks_uri"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint   string   `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint  string   `json:"introspection_endpoint"`
	RevocationEndpoint     string   `json:"revocation_endpoint"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
	//acr_values_supported
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IdTokenSigningAlgorithmsSupported []string `json:"id_token_signing_alg_values_supported"`
	//id_token_encryption_alg_values_supported
	//id_token_encryption_enc_values_supported
	//userinfo_signing_alg_values_supported
	//userinfo_encryption_alg_values_supported
	//userinfo_encryption_enc_values_supported
	//request_object_signing_alg_values_supported
	//request_object_encryption_alg_values_supported
	//request_object_encryption_enc_values_supported
	//token_endpoint_auth_methods_supported
	//token_endpoint_auth_signing_alg_values_supported
	//display_values_supported
	//claim_types_supported
	//claims_supported
	//service_documentation
	//claims_locales_supported
	//ui_locales_supported
	//claims_parameter_supported
}

// OpenID Connect Discovery
// https://openid.net/specs/openid-connect-discovery-1_0.html
func WellKnownConfigurationHandler(w http.ResponseWriter, r *http.Request) {

	config := &openIdConfig{
		Issuer:                            "http://localhost:5000",
		AuthorizationEndpoint:             "http://localhost:5000/auth/authorize",
		TokenEndpoint:                     "http://localhost:5000/auth/token",
		UserInfoEndpoint:                  "http://localhost:5000/auth/userinfo",
		ResponseTypesSupported:            make([]string, 0),
		SubjectTypesSupported:             make([]string, 0),
		IdTokenSigningAlgorithmsSupported: make([]string, 0),
	}
	config.ResponseTypesSupported = append(config.ResponseTypesSupported, "code")
	config.SubjectTypesSupported = append(config.SubjectTypesSupported, "public")
	config.IdTokenSigningAlgorithmsSupported = append(config.IdTokenSigningAlgorithmsSupported, "RS256")

	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	json.NewEncoder(w).Encode(config)
}
