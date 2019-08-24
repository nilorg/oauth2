package oauth2

import "context"

// AuthorizationGranter 四种授权方式（authorization grant ）
type AuthorizationGranter interface {
	// 授权码（authorization-code）
	AuthorizeAuthorizationCode(ctx context.Context, clientID, redirectUri, scope, state string) (string, error)
	TokenAuthorizationCode(ctx context.Context, code, redirectUri string) (*TokenResponseModel, error)
	// 隐藏式（implicit）
	AuthorizeImplicit(ctx context.Context, clientID, redirectUri, scope, state string) (*TokenResponseModel, error)
	// 密码式（password）
	TokenResourceOwnerPasswordCredentials(ctx context.Context, username, password string) (*TokenResponseModel, error)
	// 客户端凭证（client credentials）
	TokenClientCredentials(ctx context.Context) (*TokenResponseModel, error)
	// 刷新Token
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResponseModel, error)
}
