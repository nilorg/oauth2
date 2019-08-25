package oauth2

// VerifyClientFunc 验证客户端委托
type VerifyClientFunc func(clientID string) (basic *ClientBasic, err error)

// VerifyAuthorizationFunc 验证授权委托
type VerifyAuthorizationFunc func(clientID, redirectUri string, scope []string) (err error)

// GenerateCodeFunc 生成Code委托
type GenerateCodeFunc func(clientID, redirectUri string, scope []string) (code string, err error)

// VerifyCodeFunc 验证Code委托
type VerifyCodeFunc func(code, clientID, redirectUri string) (value *CodeValue, err error)

// VerifyPasswordFunc 验证账号密码委托
type VerifyPasswordFunc func(username, password string, scope []string) (err error)

//// VerifyScopeFunc 验证范围
//type VerifyScopeFunc func(clientID, redirectUri string, scope []string) (err error)

// VerifyCredentialsScopeFunc 验证客户端凭证范围委托
type VerifyCredentialsScopeFunc func(clientID string, scope []string) (err error)
