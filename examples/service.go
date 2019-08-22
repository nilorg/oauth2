package examples

import "github.com/nilorg/oauth2"

type DefaultService struct {
}

func (service *DefaultService) AuthorizeAuthorizationCode(clientID, redirectUri, scope, state string) (code string, err error) {

	return
}
func (service *DefaultService) TokenAuthorizationCode(code, redirectUri string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (service *DefaultService) AuthorizeImplicit(clientID, redirectUri, scope, state string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (service *DefaultService) TokenResourceOwnerPasswordCredentials(username, password string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (service *DefaultService) TokenClientredentials(scope string) (model *oauth2.TokenResponseModel, err error) {

	return
}
func (service *DefaultService) RefreshToken(refreshToken string) (model *oauth2.TokenResponseModel, err error) {

	return
}

func NewDefaultService() *DefaultService {
	return &DefaultService{}
}