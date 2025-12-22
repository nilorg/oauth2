package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nilorg/oauth2"
)

var (
	clients = map[string]string{
		"oauth2_client": "password",
	}
)

func main() {
	// ============= 示例1: SaaS多租户场景 - 动态Issuer =============
	// Example 1: SaaS multi-tenant scenario - Dynamic Issuer
	srv := oauth2.NewServer(
		// 动态Issuer：根据请求的Host自动生成JWT的iss字段
		// Dynamic Issuer: automatically generate JWT iss field based on request Host
		oauth2.ServerIssuerFunc(func(ctx context.Context, req oauth2.IssuerRequest) string {
			// SaaS场景：每个租户有独立的域名
			// SaaS scenario: each tenant has its own domain
			// 例如：tenant1.example.com, tenant2.example.com
			return fmt.Sprintf("%s://%s", req.Scheme, req.Host)
		}),
		// 启用设备授权端点
		oauth2.ServerDeviceAuthorizationEndpointEnabled(true),
	)

	// ============= 示例2: 反向代理场景 =============
	// Example 2: Reverse proxy scenario
	// 如果服务在反向代理（如Nginx、Traefik）后面，使用以下配置：
	// If the service is behind a reverse proxy (e.g., Nginx, Traefik), use:
	//
	// srv := oauth2.NewServer(
	//     // 使用内置的反向代理支持，从 X-Forwarded-* 头部获取信息
	//     oauth2.ServerIssuerRequestFunc(oauth2.ProxyIssuerRequestFunc),
	//     oauth2.ServerIssuerFunc(func(ctx context.Context, req oauth2.IssuerRequest) string {
	//         return fmt.Sprintf("%s://%s", req.Scheme, req.Host)
	//     }),
	// )

	// ============= 示例3: 自定义IssuerRequest提取 =============
	// Example 3: Custom IssuerRequest extraction
	//
	// srv := oauth2.NewServer(
	//     oauth2.ServerIssuerRequestFunc(func(r *http.Request) oauth2.IssuerRequest {
	//         // 从自定义头部获取租户信息
	//         // Get tenant info from custom headers
	//         return oauth2.IssuerRequest{
	//             Host:   r.Header.Get("X-Tenant-Domain"),
	//             Scheme: r.Header.Get("X-Forwarded-Proto"),
	//         }
	//     }),
	//     oauth2.ServerIssuerFunc(func(ctx context.Context, req oauth2.IssuerRequest) string {
	//         return fmt.Sprintf("%s://%s", req.Scheme, req.Host)
	//     }),
	// )

	// ============= 示例4: 静态Issuer（单租户场景）=============
	// Example 4: Static Issuer (single tenant scenario)
	//
	// srv := oauth2.NewServer(
	//     oauth2.ServerIssuer("https://auth.example.com"),
	// )

	srv.VerifyClient = func(ctx context.Context, basic *oauth2.ClientBasic) (err error) {
		pwd, ok := clients[basic.ID]
		if !ok {
			err = oauth2.ErrInvalidClient
			return
		}
		if basic.Secret != pwd {
			err = oauth2.ErrInvalidClient
			return
		}
		return
	}
	srv.VerifyClientID = func(ctx context.Context, clientID string) (err error) {
		_, ok := clients[clientID]
		if !ok {
			err = oauth2.ErrInvalidClient
		}
		return
	}
	srv.VerifyCode = func(ctx context.Context, code, clientID, redirectURI string) (value *oauth2.CodeValue, err error) {
		// 查询缓存/数据库中的code信息
		// Query code info from cache/database
		value = &oauth2.CodeValue{
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Scope:       []string{"read", "write"},
		}
		return
	}
	srv.GenerateCode = func(ctx context.Context, clientID, openID, redirectURI string, scope []string) (code string, err error) {
		code = oauth2.RandomCode()
		// 将code存储到缓存/数据库
		// Store code to cache/database
		return
	}
	srv.VerifyRedirectURI = func(ctx context.Context, clientID, redirectURI string) (err error) {
		// 验证redirect_uri是否在白名单中
		// Verify if redirect_uri is in whitelist
		return
	}

	srv.VerifyPassword = func(ctx context.Context, clientID, username, password string) (openID string, err error) {
		// 验证用户名密码
		// Verify username and password
		if username != "admin" || password != "123456" {
			err = oauth2.ErrUnauthorizedClient
			return
		}
		openID = "user_001"
		return
	}

	srv.VerifyScope = func(ctx context.Context, scopes []string, clientID string) (err error) {
		// 验证scope是否在允许范围内
		// Verify if scope is allowed
		return
	}

	srv.VerifyGrantType = func(ctx context.Context, clientID, grantType string) (err error) {
		// 验证client是否支持该grant_type
		// Verify if client supports this grant_type
		return
	}

	// ============= JWT密钥配置 =============
	// JWT Key Configuration

	// 方式1: 静态密钥（单租户）
	// Option 1: Static key (single tenant)
	srv.AccessToken = oauth2.NewDefaultAccessToken([]byte("your-jwt-secret-key"))

	// 方式2: 多租户动态密钥
	// Option 2: Multi-tenant dynamic key
	//
	// srv.AccessToken = oauth2.NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
	//     // 根据 issuer 从数据库/配置中获取对应租户的密钥
	//     // Get tenant's key from database/config based on issuer
	//     // 例如: issuer = "https://tenant1.example.com"
	//     tenantKeys := map[string][]byte{
	//         "https://tenant1.example.com": []byte("tenant1-secret-key"),
	//         "https://tenant2.example.com": []byte("tenant2-secret-key"),
	//     }
	//     if key, ok := tenantKeys[issuer]; ok {
	//         return key
	//     }
	//     return []byte("default-secret-key")
	// })

	srv.GenerateDeviceAuthorization = func(ctx context.Context, issuer, verificationURI, clientID string, scope []string) (resp *oauth2.DeviceAuthorizationResponse, err error) {
		// issuer 会根据请求动态生成，例如 "https://tenant1.example.com"
		// issuer is dynamically generated based on request, e.g., "https://tenant1.example.com"
		resp = &oauth2.DeviceAuthorizationResponse{
			DeviceCode:              oauth2.RandomCode(),
			UserCode:                oauth2.RandomUserCode(),
			VerificationURI:         issuer + verificationURI,
			VerificationURIComplete: "",
			ExpiresIn:               1800,
			Interval:                5,
		}
		return
	}

	srv.VerifyDeviceCode = func(ctx context.Context, deviceCode, clientID string) (value *oauth2.DeviceCodeValue, err error) {
		// 验证device_code
		// err = oauth2.ErrAuthorizationPending // 用户尚未授权
		// err = oauth2.ErrSlowDown             // 请求过于频繁
		// err = oauth2.ErrAccessDenied         // 用户拒绝授权
		// err = oauth2.ErrExpiredToken         // device_code已过期
		return
	}

	if err := srv.InitWithError(); err != nil {
		panic(err)
	}

	// =============Gin路由配置=============
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

	fmt.Println("=========================================")
	fmt.Println("OAuth2 Server started at :8003")
	fmt.Println("=========================================")
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  - GET  /oauth2/authorize")
	fmt.Println("  - POST /oauth2/token")
	fmt.Println("  - POST /oauth2/device_authorization")
	fmt.Println("")
	fmt.Println("SaaS多租户特性 / SaaS Multi-tenant Feature:")
	fmt.Println("  JWT的issuer将根据请求Host动态生成")
	fmt.Println("  JWT issuer will be dynamically generated based on request Host")
	fmt.Println("")
	fmt.Println("测试命令 / Test Command:")
	fmt.Println("  curl -X POST http://localhost:8003/oauth2/token \\")
	fmt.Println("    -u oauth2_client:password \\")
	fmt.Println("    -d 'grant_type=password&username=admin&password=123456&scope=read'")
	fmt.Println("")

	if err := http.ListenAndServe(":8003", r); err != nil {
		fmt.Printf("%+v\n", err)
	}
}
