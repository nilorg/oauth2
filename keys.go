package oauth2

const (
	// ResponseTypeKey 响应类型 / Response type parameter key
	ResponseTypeKey = "response_type"
	// ClientIDKey 客户端ID / Client identifier parameter key
	ClientIDKey = "client_id"
	// ClientSecretKey 客户端密钥 / Client secret parameter key
	ClientSecretKey = "client_secret"
	// RedirectURIKey 重定向URI / Redirect URI parameter key
	RedirectURIKey = "redirect_uri"
	// ScopeKey 授权范围 / Scope parameter key
	ScopeKey = "scope"
	// StateKey 状态码，用于防止CSRF攻击 / State parameter key for CSRF protection
	StateKey = "state"
	// GrantTypeKey 授权类型 / Grant type parameter key
	GrantTypeKey = "grant_type"
	// CodeKey 授权码 / Authorization code parameter key
	CodeKey = "code"
	// TokenKey 令牌 / Token parameter key
	TokenKey = "token"
	// ErrorKey 错误信息 / Error parameter key
	ErrorKey = "error"
	// AccessTokenKey 访问令牌 / Access token parameter key
	AccessTokenKey = "access_token"
	// TokenTypeKey 令牌类型 / Token type parameter key
	TokenTypeKey = "token_type"
	// ClientCredentialsKey 客户端凭证模式 / Client credentials grant type
	ClientCredentialsKey = "client_credentials"
	// PasswordKey 密码模式 / Resource owner password credentials grant type
	PasswordKey = "password"
	// UsernameKey 用户名 / Username parameter key
	UsernameKey = "username"
	// RefreshTokenKey 刷新令牌 / Refresh token parameter key
	RefreshTokenKey = "refresh_token"
	// AuthorizationCodeKey 授权码模式 / Authorization code grant type
	AuthorizationCodeKey = "authorization_code"
	// DeviceCodeKey 设备码模式 / Device code grant type
	DeviceCodeKey = "device_code"
	// UrnIetfParamsOAuthGrantTypeDeviceCodeKey 设备码模式URN格式 / Device code grant type in URN format (RFC 8628)
	UrnIetfParamsOAuthGrantTypeDeviceCodeKey = "urn:ietf:params:oauth:grant-type:device_code"
	// TokenTypeHintKey 令牌类型提示 / Token type hint parameter key
	TokenTypeHintKey = "token_type_hint"
	// ImplicitKey 隐式授权模式 / Implicit grant type
	ImplicitKey = "implicit"
)
