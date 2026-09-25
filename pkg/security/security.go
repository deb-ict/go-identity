// Package security contains the cryptographic helpers of the identity server.
package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// ErrMismatch is returned when a password or secret doesn't match the hash.
var ErrMismatch = errors.New("security: secret mismatch")

// PasswordHasher hashes and verifies user passwords and client secrets.
type PasswordHasher interface {
	Hash(secret string) (string, error)
	Verify(hash string, secret string) error
}

// BcryptHasher is a PasswordHasher using bcrypt.
type BcryptHasher struct {
	Cost int
}

// NewBcryptHasher creates a bcrypt hasher. A cost <= 0 uses bcrypt.DefaultCost.
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{Cost: cost}
}

func (h *BcryptHasher) Hash(secret string) (string, error) {
	// bcrypt only uses the first 72 bytes, pre-hash longer secrets so they are not truncated.
	hash, err := bcrypt.GenerateFromPassword(prehash(secret), h.Cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (h *BcryptHasher) Verify(hash string, secret string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), prehash(secret))
	if err != nil {
		return ErrMismatch
	}
	return nil
}

func prehash(secret string) []byte {
	if len(secret) <= 72 {
		return []byte(secret)
	}
	sum := sha256.Sum256([]byte(secret))
	return []byte(base64.RawStdEncoding.EncodeToString(sum[:]))
}

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("security: failed to read random bytes: %v", err))
	}
	return b
}

// RandomToken returns a URL-safe random token with n bytes of entropy.
func RandomToken(n int) string {
	return base64.RawURLEncoding.EncodeToString(RandomBytes(n))
}

// NewToken returns a URL-safe random token with 256 bits of entropy.
func NewToken() string {
	return RandomToken(32)
}

// NewId returns a random (version 4) UUID.
func NewId() string {
	b := RandomBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// HashToken returns the SHA-256 hash (hex) of a high entropy token. Tokens are stored hashed,
// so a leaked database can't be used to impersonate clients or users.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Equal compares two strings in constant time.
func Equal(a string, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
