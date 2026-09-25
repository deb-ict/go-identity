package security

import (
	"crypto/sha256"
	"encoding/base64"
)

// PKCE (RFC 7636) code challenge methods.
const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

// IsValidCodeVerifier checks the code_verifier / code_challenge syntax:
// 43 to 128 characters of [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~" (RFC 7636 section 4.1).
func IsValidCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

// IsSupportedCodeChallengeMethod checks the code_challenge_method.
func IsSupportedCodeChallengeMethod(method string) bool {
	return method == CodeChallengeMethodPlain || method == CodeChallengeMethodS256
}

// S256Challenge computes BASE64URL(SHA256(ASCII(code_verifier))).
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyCodeChallenge verifies the code_verifier against the stored challenge (RFC 7636 section 4.6).
func VerifyCodeChallenge(challenge string, method string, verifier string) bool {
	if !IsValidCodeVerifier(verifier) {
		return false
	}
	switch method {
	case CodeChallengeMethodS256:
		return Equal(S256Challenge(verifier), challenge)
	case CodeChallengeMethodPlain, "":
		return Equal(verifier, challenge)
	default:
		return false
	}
}
