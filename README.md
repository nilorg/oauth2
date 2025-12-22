# oauth2

OAuth 2.0 授权框架的 Go 语言实现，支持 SaaS 多租户场景。

Go implementation of OAuth 2.0 Authorization Framework with SaaS multi-tenant support.

## Features / 特性

- ✅ 授权码模式 (Authorization Code)
- ✅ 简化模式 (Implicit)
- ✅ 密码模式 (Resource Owner Password Credentials)
- ✅ 客户端凭证模式 (Client Credentials)
- ✅ 设备授权模式 (Device Code) - [RFC 8628](https://tools.ietf.org/html/rfc8628)
- ✅ 令牌内省 (Token Introspection) - [RFC 7662](https://tools.ietf.org/html/rfc7662)
- ✅ 令牌撤销 (Token Revocation) - [RFC 7009](https://tools.ietf.org/html/rfc7009)
- ✅ **SaaS 多租户动态 Issuer** - 根据请求域名动态生成 JWT issuer
- ✅ **SaaS 多租户动态 JWT 密钥** - 每个租户使用独立的签名密钥
- ✅ **反向代理支持** - 支持 X-Forwarded-* 头部

## Installation / 安装

```bash
go get -u github.com/nilorg/oauth2
```

## Import / 导入

```go
import "github.com/nilorg/oauth2"
```

## Quick Start / 快速开始

### 基础用法 / Basic Usage

```go
srv := oauth2.NewServer()
// 配置回调函数...
srv.InitWithError()
```

### SaaS 多租户场景 / SaaS Multi-tenant Scenario

```go
srv := oauth2.NewServer(
    // 动态 Issuer：根据请求 Host 自动生成 JWT 的 iss 字段
    oauth2.ServerIssuerFunc(func(ctx context.Context, req oauth2.IssuerRequest) string {
        // req.Host   = "tenant1.example.com"
        // req.Scheme = "https"
        return fmt.Sprintf("%s://%s", req.Scheme, req.Host)
    }),
)
```

### 反向代理场景 / Reverse Proxy Scenario

```go
srv := oauth2.NewServer(
    // 使用内置的反向代理支持，从 X-Forwarded-* 头部获取信息
    oauth2.ServerIssuerRequestFunc(oauth2.ProxyIssuerRequestFunc),
    oauth2.ServerIssuerFunc(func(ctx context.Context, req oauth2.IssuerRequest) string {
        return fmt.Sprintf("%s://%s", req.Scheme, req.Host)
    }),
)
```

### 自定义 IssuerRequest 提取 / Custom IssuerRequest Extraction

```go
srv := oauth2.NewServer(
    oauth2.ServerIssuerRequestFunc(func(r *http.Request) oauth2.IssuerRequest {
        return oauth2.IssuerRequest{
            Host:   r.Header.Get("X-Tenant-Domain"),
            Scheme: r.Header.Get("X-Forwarded-Proto"),
        }
    }),
    oauth2.ServerIssuerFunc(func(ctx context.Context, req oauth2.IssuerRequest) string {
        return fmt.Sprintf("%s://%s", req.Scheme, req.Host)
    }),
)
```

### 静态 Issuer（单租户）/ Static Issuer (Single Tenant)

```go
srv := oauth2.NewServer(
    oauth2.ServerIssuer("https://auth.example.com"),
)
```

### 多租户 JWT 密钥 / Multi-tenant JWT Key

```go
// 每个租户使用独立的 JWT 签名密钥
srv.AccessToken = oauth2.NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
    // issuer = "https://tenant1.example.com"
    // 根据 issuer 从数据库/配置中获取对应租户的密钥
    return getTenantJwtKey(issuer)
})
```

## Examples / 示例

[oauth2-server](https://github.com/nilorg/oauth2-server)

[server/client examples](https://github.com/nilorg/oauth2/tree/master/examples)

## Documentation / 文档参考

1. [《理解OAuth 2.0》阮一峰](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)
2. [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
3. [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)
4. [RFC 7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
5. [RFC 7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)

## Grant Types / 授权模式

### Authorization Code / 授权码模式
授权码模式是功能最完整、流程最严密的授权模式。它的特点就是通过客户端的后台服务器，与"服务提供商"的认证服务器进行互动。

### Implicit / 简化模式
简化模式不通过第三方应用程序的服务器，直接在浏览器中向认证服务器申请令牌，跳过了"授权码"这个步骤。

### Resource Owner Password Credentials / 密码模式
用户向客户端提供自己的用户名和密码，客户端使用这些信息向"服务商提供商"索要授权。

### Client Credentials / 客户端凭证模式
客户端以自己的名义，而不是以用户的名义，向"服务提供商"进行认证。

### Device Code / 设备模式
设备授权模式用于无法输入的设备（如智能电视、IoT设备等）。

## Server Configuration / 服务器配置

### Server Options / 服务器选项

| Option | Description |
|--------|-------------|
| `ServerLogger(log)` | 设置日志记录器 |
| `ServerIssuer(issuer)` | 设置静态 JWT issuer |
| `ServerIssuerFunc(fn)` | 设置动态 JWT issuer 函数（SaaS多租户） |
| `ServerIssuerRequestFunc(fn)` | 设置从HTTP请求提取信息的函数 |
| `ServerDeviceAuthorizationEndpointEnabled(bool)` | 启用设备授权端点 |
| `ServerIntrospectEndpointEnabled(bool)` | 启用令牌内省端点 |
| `ServerTokenRevocationEnabled(bool)` | 启用令牌撤销端点 |

### AccessToken 配置 / AccessToken Configuration

| Function | Description |
|----------|-------------|
| `NewDefaultAccessToken(key)` | 创建静态密钥的 AccessToken 处理器（单租户） |
| `NewMultiTenantAccessToken(fn)` | 创建动态密钥的 AccessToken 处理器（多租户） |

## Complete Server Example / 完整服务器示例

```go
package main

import (
    "context"
    "fmt"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/nilorg/oauth2"
)

var clients = map[string]string{
    "oauth2_client": "password",
}

func main() {
    srv := oauth2.NewServer(
        // SaaS多租户：动态Issuer
        oauth2.ServerIssuerFunc(func(ctx context.Context, req oauth2.IssuerRequest) string {
            return fmt.Sprintf("%s://%s", req.Scheme, req.Host)
        }),
        oauth2.ServerDeviceAuthorizationEndpointEnabled(true),
    )

    srv.VerifyClient = func(ctx context.Context, basic *oauth2.ClientBasic) (err error) {
        pwd, ok := clients[basic.ID]
        if !ok || basic.Secret != pwd {
            return oauth2.ErrInvalidClient
        }
        return nil
    }

    srv.VerifyClientID = func(ctx context.Context, clientID string) (err error) {
        if _, ok := clients[clientID]; !ok {
            return oauth2.ErrInvalidClient
        }
        return nil
    }

    srv.VerifyCode = func(ctx context.Context, code, clientID, redirectURI string) (*oauth2.CodeValue, error) {
        return &oauth2.CodeValue{
            ClientID:    clientID,
            RedirectURI: redirectURI,
            Scope:       []string{"read", "write"},
        }, nil
    }

    srv.GenerateCode = func(ctx context.Context, clientID, openID, redirectURI string, scope []string) (string, error) {
        return oauth2.RandomCode(), nil
    }

    srv.VerifyRedirectURI = func(ctx context.Context, clientID, redirectURI string) error {
        return nil
    }

    srv.VerifyPassword = func(ctx context.Context, clientID, username, password string) (string, error) {
        if username == "admin" && password == "123456" {
            return "user_001", nil
        }
        return "", oauth2.ErrUnauthorizedClient
    }

    srv.VerifyScope = func(ctx context.Context, scopes []string, clientID string) error {
        return nil
    }

    srv.VerifyGrantType = func(ctx context.Context, clientID, grantType string) error {
        return nil
    }

    srv.AccessToken = oauth2.NewDefaultAccessToken([]byte("your-jwt-secret"))

    srv.GenerateDeviceAuthorization = func(ctx context.Context, issuer, verificationURI, clientID string, scope []string) (*oauth2.DeviceAuthorizationResponse, error) {
        return &oauth2.DeviceAuthorizationResponse{
            DeviceCode:      oauth2.RandomCode(),
            UserCode:        oauth2.RandomUserCode(),
            VerificationURI: issuer + verificationURI,
            ExpiresIn:       1800,
            Interval:        5,
        }, nil
    }

    srv.VerifyDeviceCode = func(ctx context.Context, deviceCode, clientID string) (*oauth2.DeviceCodeValue, error) {
        return nil, nil
    }

    if err := srv.InitWithError(); err != nil {
        panic(err)
    }

    r := gin.Default()
    oauth2Group := r.Group("/oauth2")
    {
        oauth2Group.GET("/authorize", func(c *gin.Context) {
            srv.HandleAuthorize(c.Writer, c.Request)
        })
        oauth2Group.POST("/token", func(c *gin.Context) {
            srv.HandleToken(c.Writer, c.Request)
        })
        oauth2Group.POST("/device_authorization", func(c *gin.Context) {
            srv.HandleDeviceAuthorization(c.Writer, c.Request)
        })
    }

    http.ListenAndServe(":8003", r)
}
```

## Test / 测试

```bash
# Password Grant
curl -X POST http://localhost:8003/oauth2/token \
  -u oauth2_client:password \
  -d 'grant_type=password&username=admin&password=123456&scope=read'

# Client Credentials Grant  
curl -X POST http://localhost:8003/oauth2/token \
  -u oauth2_client:password \
  -d 'grant_type=client_credentials&scope=read'
```

## JWT Payload / JWT 载荷

标准声明 (Registered Claims)：

| Claim | Description |
|-------|-------------|
| `iss` | 令牌颁发者 (Issuer) - 在SaaS场景下会动态生成 |
| `sub` | 令牌主体 (Subject) - 通常是用户标识 |
| `aud` | 令牌受众 (Audience) |
| `exp` | 过期时间 (Expiration Time) |
| `nbf` | 生效时间 (Not Before) |
| `iat` | 颁发时间 (Issued At) |
| `jti` | 令牌唯一标识 (JWT ID) |

## License

MIT