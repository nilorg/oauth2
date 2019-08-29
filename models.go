package oauth2

import (
	"time"
)

type TokenResponse struct {
	AccessToken      string      `json:"access_token"`
	TokenType        string      `json:"token_type,omitempty"`
	ExpiresIn        int64       `json:"expires_in"`
	RefreshToken     string      `json:"refresh_token,omitempty"`
	ExampleParameter interface{} `json:"example_parameter,omitempty"`
	Scope            string      `json:"scope,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type CodeValue struct {
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scope       []string `json:"scope"`
}

type ClientBasic struct {
	ID     string `json:"client_id"`
	Secret string `json:"client_secret"`
}

func (client *ClientBasic) GenerateAccessToken(claims *JwtClaims) (token string, err error) {
	if claims.Issuer == "" {
		claims.Issuer = DefaultJwtIssuer
	}
	claims.Subject = client.ID
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()
	}
	claims.IssuedAt = time.Now().Unix()
	claims.NotBefore = time.Now().Unix()
	token, err = NewAccessToken(claims, []byte(client.ID+client.Secret))
	if err != nil {
		err = ErrServerError
	}
	return
}

func (client *ClientBasic) GenerateRefreshToken(issuer, accessToken string) (token string, err error) {
	claims := NewJwtClaims()
	if claims.Issuer == "" {
		claims.Issuer = DefaultJwtIssuer
	}
	claims.IssuedAt = time.Now().Unix()
	claims.NotBefore = time.Now().Unix()
	claims.Subject = client.ID
	claims.ExpiresAt = time.Now().Add(RefreshTokenExpire).Unix()
	claims.Subject = ScopeRefreshToken
	claims.Id = accessToken
	return newJwtToken(claims, []byte(client.ID+client.Secret))
}

func (client *ClientBasic) ParseAccessToken(accessToken string) (claims *JwtClaims, err error) {
	claims, err = ParseAccessToken(accessToken, []byte(client.ID+client.Secret))
	if err != nil {
		err = ErrServerError
	}
	if claims.Valid() != nil {
		err = ErrAccessDenied
	}
	return
}
