package main

import (
	"context"
	"github.com/nilorg/oauth2"
	"time"
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
func (ag *AuthorizationGrant) TokenResourceOwnerPasswordCredentials(ctx context.Context, username, password, scope string) (model *oauth2.TokenResponseModel, err error) {
	//var basic *oauth2.ClientBasic
	//basic, err = oauth2.ClientBasicFromContext(ctx)
	//if err != nil {
	//	return
	//}

	if username != "a" || password != "b" {
		err = oauth2.ErrAccessDenied
	}

	return
}
func (ag *AuthorizationGrant) TokenClientCredentials(ctx context.Context, scope string) (model *oauth2.TokenResponseModel, err error) {
	var basic *oauth2.ClientBasic
	basic, err = oauth2.ClientBasicFromContext(ctx)
	if err != nil {
		return
	}
	claims := oauth2.NewJwtClaims()
	var token string
	token, err = basic.GenerateAccessToken(claims)
	if err != nil {
		return
	}
	model = &oauth2.TokenResponseModel{
		AccessToken:      token,
		TokenType:        oauth2.TokenTypeBearer,
		ExpiresIn:        claims.ExpiresAt,
		RefreshToken:     "",
		ExampleParameter: "",
		Scope:            scope,
	}
	return
}
func (ag *AuthorizationGrant) RefreshToken(ctx context.Context, refreshToken string) (model *oauth2.TokenResponseModel, err error) {
	var basic *oauth2.ClientBasic
	basic, err = oauth2.ClientBasicFromContext(ctx)
	if err != nil {
		return
	}
	claims := oauth2.NewJwtClaims()
	claims, err = basic.ParseAccessToken(refreshToken)
	if err != nil {
		return
	}

	if claims.Scope != oauth2.ScopeRefreshToken {
		err = oauth2.ErrInvalidScope
		return
	}

	claims.ExpiresAt = time.Now().Add(oauth2.AccessTokenExpire).Unix()
	var token string
	token, err = basic.GenerateAccessToken(claims)
	if err != nil {
		return
	}
	model = &oauth2.TokenResponseModel{
		AccessToken: token,
		TokenType:   oauth2.TokenTypeBearer,
		ExpiresIn:   claims.ExpiresAt,
		//RefreshToken:     "",
		//ExampleParameter: nil,
		Scope: oauth2.ScopeRefreshToken,
	}
	return
}

func NewAuthorizationGrant() *AuthorizationGrant {
	return &AuthorizationGrant{}
}
