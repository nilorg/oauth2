package main

import (
	"context"
	"github.com/nilorg/oauth2"
)

type AuthorizationGrant struct {
}

func (ag *AuthorizationGrant) AuthorizeAuthorizationCode(ctx context.Context, clientID, redirectUri, scope, state string) (code string, err error) {

	return
}
func (ag *AuthorizationGrant) TokenAuthorizationCode(ctx context.Context, code, redirectUri string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (ag *AuthorizationGrant) AuthorizeImplicit(ctx context.Context, clientID, redirectUri, scope, state string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (ag *AuthorizationGrant) TokenResourceOwnerPasswordCredentials(ctx context.Context, username, password string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (ag *AuthorizationGrant) TokenClientCredentials(ctx context.Context) (model *oauth2.TokenResponseModel, err error) {
	var basic *oauth2.ClientBasic
	basic, err = oauth2.ClientBasicFromContext(ctx)
	if err != nil {
		return
	}
	claims := oauth2.NewJwtClaims()
	var token string
	token, err = basic.GenerateAccessToken(claims, oauth2.AccessTokenExpire)
	if err != nil {
		return
	}
	var tefreshToken string
	tefreshToken, err = basic.GenerateRefreshToken()
	if err != nil {
		return
	}
	model = &oauth2.TokenResponseModel{
		AccessToken:      token,
		TokenType:        oauth2.TokenTypeBearer,
		ExpiresIn:        claims.ExpiresAt,
		RefreshToken:     tefreshToken,
		ExampleParameter: "",
		Scope:            "",
	}
	return
}
func (ag *AuthorizationGrant) RefreshToken(ctx context.Context, refreshToken string) (model *oauth2.TokenResponseModel, err error) {

	return
}

func NewAuthorizationGrant() *AuthorizationGrant {
	return &AuthorizationGrant{}
}
