package oauth2

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

// JwtClaims ...
type JwtClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
}

// NewJwtClaims ...
func NewJwtClaims(issuer, clientID, scope, redirectURI, openID string) *JwtClaims {
	currTime := time.Now()
	return &JwtClaims{
		StandardClaims: jwt.StandardClaims{
			// Audience = aud,接收jwt的一方
			Audience: redirectURI,
			// ExpiresAt = exp
			ExpiresAt: currTime.Add(AccessTokenExpire).Unix(),
			// IssuedAt = iat,jwt的签发时间
			IssuedAt: currTime.Unix(),
			// Issuer = iss,jwt签发者
			Issuer: issuer,
			// NotBefore = nbf,定义在什么时间之前，该jwt都是不可用的
			NotBefore: currTime.Unix(),
			// Subject = sub,jwt所面向的用户
			Subject: openID,
		},
		Scope: scope,
	}
}

func newJwtToken(claims jwt.Claims, jwtVerifyKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtVerifyKey)
}

// NewAccessToken ...
func NewAccessToken(claims *JwtClaims, jwtVerifyKey []byte) (string, error) {
	return newJwtToken(claims, jwtVerifyKey)
}

// ParseAccessToken ...
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
