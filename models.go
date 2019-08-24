package oauth2

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

type TokenResponseModel struct {
	AccessToken      string      `json:"access_token"`
	TokenType        string      `json:"token_type"`
	ExpiresIn        int64       `json:"expires_in"`
	RefreshToken     string      `json:"refresh_token"`
	ExampleParameter interface{} `json:"example_parameter"`
	Scope            string      `json:"scope"`
}

type ErrorResponseModel struct {
	Error string `json:"error"`
}

type ClientBasic struct {
	ID     string `json:"client_id"`
	Secret string `json:"client_secret"`
}

func (client *ClientBasic) GenerateAccessToken(claims *JwtClaims, tokenExpire time.Duration) (token string, err error) {
	token, err = NewAccessToken(claims, []byte(client.ID+client.Secret), tokenExpire)
	if err != nil {
		err = ErrServerError
	}
	return
}

func (client *ClientBasic) GenerateRefreshToken() (token string, err error) {
	claims := jwt.StandardClaims{}
	claims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()
	return newJwtToken(claims, []byte(client.ID+client.Secret))
}

func (client *ClientBasic) ParseAccessToken(accessToken string) (claims *JwtClaims, err error) {
	claims, err = ParseAccessToken(accessToken, []byte(client.ID+client.Secret))
	if err != nil {
		err = ErrServerError
	}
	return
}
