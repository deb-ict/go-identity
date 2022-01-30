package identity

import (
	"golang.org/x/crypto/bcrypt"
)

func NewSecretHasher() SecretHasher {
	return &secretHasher{}
}

type secretHasher struct {
}

func (h *secretHasher) VerifySecret(hash string, secret string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
}

func (h *secretHasher) HashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
