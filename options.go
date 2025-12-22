package oauth2

import (
	"context"
	"net/http"
)

// IssuerRequest 用于动态获取Issuer的请求信息，只包含必要字段
// Request info for dynamic Issuer retrieval, contains only necessary fields
type IssuerRequest struct {
	Host   string // 请求的Host，如 "tenant1.example.com"
	Scheme string // 协议，"http" 或 "https"
}

// IssuerFunc 动态获取Issuer的函数类型，用于SaaS多租户场景
// Dynamic Issuer function type for SaaS multi-tenant scenarios
type IssuerFunc func(ctx context.Context, req IssuerRequest) string

// IssuerRequestFunc 从HTTP请求提取IssuerRequest的函数类型
// Function type for extracting IssuerRequest from HTTP request
type IssuerRequestFunc func(r *http.Request) IssuerRequest

// DefaultIssuerRequestFunc 默认的IssuerRequest提取函数
// Default IssuerRequest extraction function
func DefaultIssuerRequestFunc(r *http.Request) IssuerRequest {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return IssuerRequest{
		Host:   r.Host,
		Scheme: scheme,
	}
}

// ProxyIssuerRequestFunc 支持反向代理的IssuerRequest提取函数
// IssuerRequest extraction function with reverse proxy support
// 从 X-Forwarded-Proto 和 X-Forwarded-Host 头部获取信息
func ProxyIssuerRequestFunc(r *http.Request) IssuerRequest {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return IssuerRequest{
		Host:   host,
		Scheme: scheme,
	}
}

// ServerOptions server可选参数列表
type ServerOptions struct {
	Log                                Logger
	Issuer                             string            // 静态Issuer / Static Issuer
	IssuerFunc                         IssuerFunc        // 动态Issuer函数，优先级高于静态Issuer / Dynamic Issuer function, takes precedence over static Issuer
	IssuerRequestFunc                  IssuerRequestFunc // 从HTTP请求提取IssuerRequest的函数 / Function to extract IssuerRequest from HTTP request
	DeviceAuthorizationEndpointEnabled bool              // https://tools.ietf.org/html/rfc8628
	DeviceVerificationURI              string            // https://tools.ietf.org/html/rfc8628#section-3.2
	IntrospectEndpointEnabled          bool              // https://tools.ietf.org/html/rfc7662
	TokenRevocationEnabled             bool              // https://tools.ietf.org/html/rfc7009
	CustomGrantTypeEnabled             bool              // 自定义身份验证
	CustomGrantTypeAuthentication      map[string]CustomGrantTypeAuthenticationFunc
}

// GetIssuerRequest 从HTTP请求获取IssuerRequest
// Get IssuerRequest from HTTP request
func (o *ServerOptions) GetIssuerRequest(r *http.Request) IssuerRequest {
	if o.IssuerRequestFunc != nil {
		return o.IssuerRequestFunc(r)
	}
	return DefaultIssuerRequestFunc(r)
}

// GetIssuerFromContext 从上下文获取Issuer，用于内部调用
// Get Issuer from context, for internal use
func (o *ServerOptions) GetIssuerFromContext(ctx context.Context) string {
	if o.IssuerFunc != nil {
		if req, err := IssuerRequestFromContext(ctx); err == nil {
			return o.IssuerFunc(ctx, req)
		}
	}
	return o.Issuer
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

// ServerIssuerFunc 设置动态JWT颁发者函数，用于SaaS多租户场景
// Set dynamic JWT issuer function for SaaS multi-tenant scenarios
// 示例 / Example:
//
//	ServerIssuerFunc(func(ctx context.Context, req oauth2.IssuerRequest) string {
//	    // 基于请求Host动态获取Issuer / Get Issuer dynamically based on request Host
//	    return fmt.Sprintf("%s://%s", req.Scheme, req.Host)
//	})
func ServerIssuerFunc(issuerFunc IssuerFunc) ServerOption {
	return func(o *ServerOptions) {
		o.IssuerFunc = issuerFunc
	}
}

// ServerIssuerRequestFunc 设置从HTTP请求提取IssuerRequest的函数
// Set function for extracting IssuerRequest from HTTP request
// 示例 / Example:
//
//	// 使用内置的反向代理支持函数
//	ServerIssuerRequestFunc(oauth2.ProxyIssuerRequestFunc)
//
//	// 或自定义提取逻辑
//	ServerIssuerRequestFunc(func(r *http.Request) oauth2.IssuerRequest {
//	    return oauth2.IssuerRequest{
//	        Host:   r.Header.Get("X-Real-Host"),
//	        Scheme: r.Header.Get("X-Forwarded-Proto"),
//	    }
//	})
func ServerIssuerRequestFunc(issuerRequestFunc IssuerRequestFunc) ServerOption {
	return func(o *ServerOptions) {
		o.IssuerRequestFunc = issuerRequestFunc
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
