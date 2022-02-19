package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type AccessToken struct {
	Type string
}

type RefreshToken struct {
	CreatedAt time.Time
	Lifetime  time.Duration
	Token     AccessToken
	User      User
	Scopes    []string
}

type TokenManager interface {
	GenerateAccessToken(claims Claims) (string, error)
	ValidateAccessToken(value string) (Claims, error)
}

func NewJwtTokenManager() TokenManager {
	return &jwtTokenManager{
		signingKey: []byte("i_am_a_secret"),
	}
}

type jwtTokenManager struct {
	signingKey []byte
}

func (m *jwtTokenManager) GenerateAccessToken(claims Claims) (string, error) {
	jwtClaims := jwt.MapClaims(claims)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	signed, err := token.SignedString([]byte(m.signingKey))
	if err != nil {
		return "", err
	}
	return signed, nil
}

func (m *jwtTokenManager) ValidateAccessToken(value string) (Claims, error) {
	claims := Claims{}
	token, err := jwt.Parse(value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.signingKey, nil
	})
	if err != nil {
		return claims, err
	}
	if !token.Valid {
		return claims, errors.New("")
	}

	jwtClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return claims, errors.New("")
	}

	claims = Claims(jwtClaims)
	return claims, err
}
