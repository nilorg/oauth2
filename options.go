package oauth2

// ServerOptions server可选参数列表
type ServerOptions struct {
	Log                                Logger
	Issuer                             string
	DeviceAuthorizationEndpointEnabled bool   // https://tools.ietf.org/html/rfc8628
	DeviceVerificationURI              string // https://tools.ietf.org/html/rfc8628#section-3.2
	IntrospectEndpointEnabled          bool   // https://tools.ietf.org/html/rfc7662
	TokenRevocationEnabled             bool   // https://tools.ietf.org/html/rfc7009
	CustomGrantTypeEnabled             bool   // 自定义身份验证
	CustomGrantTypeAuthentication      map[string]CustomGrantTypeAuthenticationFunc
}

// ServerOption 为可选参数赋值的函数
type ServerOption func(*ServerOptions)

// ServerLogger 设置服务器日志记录器 / Set server logger
func ServerLogger(log Logger) ServerOption {
	return func(o *ServerOptions) {
		o.Log = log
	}
}

// ServerIssuer 设置JWT颁发者 / Set JWT issuer
func ServerIssuer(issuer string) ServerOption {
	return func(o *ServerOptions) {
		o.Issuer = issuer
	}
}

// ServerDeviceAuthorizationEndpointEnabled 启用设备授权端点 / Enable device authorization endpoint (RFC 8628)
func ServerDeviceAuthorizationEndpointEnabled(deviceAuthorizationEndpointEnabled bool) ServerOption {
	return func(o *ServerOptions) {
		o.DeviceAuthorizationEndpointEnabled = deviceAuthorizationEndpointEnabled
	}
}

// ServerDeviceVerificationURI 设置设备验证URI / Set device verification URI
func ServerDeviceVerificationURI(deviceVerificationURI string) ServerOption {
	return func(o *ServerOptions) {
		o.DeviceVerificationURI = deviceVerificationURI
	}
}

// ServerIntrospectEndpointEnabled 启用令牌内省端点 / Enable token introspection endpoint (RFC 7662)
func ServerIntrospectEndpointEnabled(introspectEndpointEnabled bool) ServerOption {
	return func(o *ServerOptions) {
		o.IntrospectEndpointEnabled = introspectEndpointEnabled
	}
}

// ServerTokenRevocationEnabled 启用令牌撤销端点 / Enable token revocation endpoint (RFC 7009)
func ServerTokenRevocationEnabled(tokenRevocationEnabled bool) ServerOption {
	return func(o *ServerOptions) {
		o.TokenRevocationEnabled = tokenRevocationEnabled
	}
}

// ServerCustomGrantTypeEnabled 启用自定义授权类型 / Enable custom grant types
func ServerCustomGrantTypeEnabled(customGrantTypeEnabled bool) ServerOption {
	return func(o *ServerOptions) {
		o.CustomGrantTypeEnabled = customGrantTypeEnabled
	}
}

// ServerCustomGrantTypeAuthentication 设置自定义授权类型认证函数 / Set custom grant type authentication functions
func ServerCustomGrantTypeAuthentication(customGrantTypeAuthentication map[string]CustomGrantTypeAuthenticationFunc) ServerOption {
	return func(o *ServerOptions) {
		o.CustomGrantTypeAuthentication = customGrantTypeAuthentication
	}
}

// newServerOptions 创建server可选参数
func newServerOptions(opts ...ServerOption) ServerOptions {
	opt := ServerOptions{
		Log:                                &DefaultLogger{},
		Issuer:                             DefaultJwtIssuer,
		DeviceAuthorizationEndpointEnabled: false,
		DeviceVerificationURI:              "/device",
		IntrospectEndpointEnabled:          false,
		TokenRevocationEnabled:             false,
		CustomGrantTypeEnabled:             false,
		CustomGrantTypeAuthentication:      make(map[string]CustomGrantTypeAuthenticationFunc),
	}
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
