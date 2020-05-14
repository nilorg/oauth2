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
func NewJwtClaims(issuer, audience, scope, openID string) *JwtClaims {
	currTime := time.Now()
	return &JwtClaims{
		StandardClaims: jwt.StandardClaims{
			// Issuer = iss,令牌颁发者。它表示该令牌是由谁创建的
			Issuer: issuer,
			// Subject = sub,令牌的主体。它表示该令牌是关于谁的
			Subject: openID,
			// Audience = aud,令牌的受众。它表示令牌的接收者
			Audience: audience,
			// ExpiresAt = exp,令牌的过期时间戳。它表示令牌将在何时过期
			ExpiresAt: currTime.Add(AccessTokenExpire).Unix(),
			// NotBefore = nbf,令牌的生效时的时间戳。它表示令牌从什么时候开始生效
			NotBefore: currTime.Unix(),
			// IssuedAt = iat,令牌颁发时的时间戳。它表示令牌是何时被创建的
			IssuedAt: currTime.Unix(),
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
