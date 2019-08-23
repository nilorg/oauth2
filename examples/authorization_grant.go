package examples

import "github.com/nilorg/oauth2"

type AuthorizationGrant struct {
}

func (ag *AuthorizationGrant) AuthorizeAuthorizationCode(clientID, redirectUri, scope, state string) (code string, err error) {

	return
}
func (ag *AuthorizationGrant) TokenAuthorizationCode(code, redirectUri string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (ag *AuthorizationGrant) AuthorizeImplicit(clientID, redirectUri, scope, state string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (ag *AuthorizationGrant) TokenResourceOwnerPasswordCredentials(username, password string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (ag *AuthorizationGrant) TokenClientCredentials(scope string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (ag *AuthorizationGrant) RefreshToken(refreshToken string) (model *oauth2.TokenResponseModel, err error) {

	return
}

func NewDefaultService() *AuthorizationGrant {
	return &AuthorizationGrant{}
}