package oauth2

type Serveer interface {
	AuthorizeAuthorizationCode(clientID, redirectUri, scope, state string) (string, error)
	TokenAuthorizationCode(code, redirectUri string) (*TokenResponseModel, error)
	AuthorizeImplicit(clientID, redirectUri, scope, state string) (*TokenResponseModel, error)
	TokenResourceOwnerPasswordCredentials(username, password string) (*TokenResponseModel, error)
	TokenClientredentials(scope string) (*TokenResponseModel, error)
	RefreshToken(refreshToken string) (*TokenResponseModel, error)
}
