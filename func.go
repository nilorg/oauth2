package oauth2

// VerifyClientFunc 验证客户端委托
type VerifyClientFunc func(clientID string) (basic *ClientBasic, err error)

// VerifyRedirectURIFunc 验证RedirectURI委托
type VerifyRedirectURIFunc func(clientID, redirectURI string) (err error)

// GenerateCodeFunc 生成Code委托
type GenerateCodeFunc func(clientID, openID, redirectURI string, scope []string) (code string, err error)

// VerifyCodeFunc 验证Code委托
type VerifyCodeFunc func(code, clientID, redirectURI string) (value *CodeValue, err error)

// VerifyPasswordFunc 验证账号密码委托
type VerifyPasswordFunc func(username, password string) (openID string, err error)

// VerifyScopeFunc 验证范围
type VerifyScopeFunc func(scope []string) (err error)
