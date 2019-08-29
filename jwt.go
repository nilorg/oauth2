package oauth2

import (
	"github.com/dgrijalva/jwt-go"
)

type JwtClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
}

func NewJwtClaims() *JwtClaims {
	return &JwtClaims{}
}

func newJwtToken(claims jwt.Claims, jwtVerifyKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtVerifyKey)
}

func NewAccessToken(claims *JwtClaims, jwtVerifyKey []byte) (string, error) {
	return newJwtToken(claims, jwtVerifyKey)
}

func ParseAccessToken(accessToken string, jwtVerifyKey []byte) (claims *JwtClaims, err error) {
	var token *jwt.Token
	token, err = jwt.ParseWithClaims(accessToken, &JwtClaims{}, func(token *jwt.Token) (i interface{}, e error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtVerifyKey, nil
	})
	if token != nil {
		var ok bool
		if claims, ok = token.Claims.(*JwtClaims); ok {
			return claims, nil
		}
	}
	return
}
