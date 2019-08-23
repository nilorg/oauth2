package oauth2

import "context"

// AuthorizationGranter 四种授权方式（authorization grant ）
type AuthorizationGranter interface {
	// 授权码（authorization-code）
	AuthorizeAuthorizationCode(clientID, redirectUri, scope, state string) (string, error)
	TokenAuthorizationCode(code, redirectUri string) (*TokenResponseModel, error)
	// 隐藏式（implicit）
	AuthorizeImplicit(clientID, redirectUri, scope, state string) (*TokenResponseModel, error)
	// 密码式（password）
	TokenResourceOwnerPasswordCredentials(username, password string) (*TokenResponseModel, error)
	// 客户端凭证（client credentials）
	TokenClientCredentials(ctx context.Context) (*TokenResponseModel, error)
	// 刷新Token
	RefreshToken(refreshToken string) (*TokenResponseModel, error)
}
