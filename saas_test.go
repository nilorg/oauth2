package oauth2

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 测试用密钥（HS256 需要 32 字节密钥）
var (
	testJwtKey     = []byte("12345678901234567890123456789012") // 32 bytes
	testTenant1Key = []byte("tenant1-key-12345678901234567890") // 32 bytes
	testTenant2Key = []byte("tenant2-key-12345678901234567890") // 32 bytes
	testDefaultKey = []byte("default-key-12345678901234567890") // 32 bytes
	testWrongKey   = []byte("wrong-key-1234567890123456789012") // 32 bytes
)

// ==================== IssuerRequest 测试 ====================

func TestDefaultIssuerRequestFunc(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		useTLS         bool
		expectedHost   string
		expectedScheme string
	}{
		{
			name:           "HTTP请求",
			host:           "tenant1.example.com",
			useTLS:         false,
			expectedHost:   "tenant1.example.com",
			expectedScheme: "http",
		},
		{
			name:           "HTTPS请求",
			host:           "tenant2.example.com",
			useTLS:         true,
			expectedHost:   "tenant2.example.com",
			expectedScheme: "https",
		},
		{
			name:           "带端口的Host",
			host:           "localhost:8080",
			useTLS:         false,
			expectedHost:   "localhost:8080",
			expectedScheme: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/oauth2/token", nil)
			req.Host = tt.host
			if tt.useTLS {
				req.TLS = &tls.ConnectionState{}
			}

			issuerReq := DefaultIssuerRequestFunc(req)

			if issuerReq.Host != tt.expectedHost {
				t.Errorf("Host = %v, want %v", issuerReq.Host, tt.expectedHost)
			}
			if issuerReq.Scheme != tt.expectedScheme {
				t.Errorf("Scheme = %v, want %v", issuerReq.Scheme, tt.expectedScheme)
			}
		})
	}
}

func TestProxyIssuerRequestFunc(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		forwardedHost  string
		forwardedProto string
		useTLS         bool
		expectedHost   string
		expectedScheme string
	}{
		{
			name:           "使用X-Forwarded头部",
			host:           "internal-server",
			forwardedHost:  "tenant1.example.com",
			forwardedProto: "https",
			useTLS:         false,
			expectedHost:   "tenant1.example.com",
			expectedScheme: "https",
		},
		{
			name:           "只有X-Forwarded-Host",
			host:           "internal-server",
			forwardedHost:  "tenant2.example.com",
			forwardedProto: "",
			useTLS:         false,
			expectedHost:   "tenant2.example.com",
			expectedScheme: "http",
		},
		{
			name:           "只有X-Forwarded-Proto",
			host:           "internal-server",
			forwardedHost:  "",
			forwardedProto: "https",
			useTLS:         false,
			expectedHost:   "internal-server",
			expectedScheme: "https",
		},
		{
			name:           "无X-Forwarded头部使用TLS",
			host:           "internal-server",
			forwardedHost:  "",
			forwardedProto: "",
			useTLS:         true,
			expectedHost:   "internal-server",
			expectedScheme: "https",
		},
		{
			name:           "无X-Forwarded头部无TLS",
			host:           "internal-server",
			forwardedHost:  "",
			forwardedProto: "",
			useTLS:         false,
			expectedHost:   "internal-server",
			expectedScheme: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/oauth2/token", nil)
			req.Host = tt.host
			if tt.forwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.forwardedHost)
			}
			if tt.forwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			}
			if tt.useTLS {
				req.TLS = &tls.ConnectionState{}
			}

			issuerReq := ProxyIssuerRequestFunc(req)

			if issuerReq.Host != tt.expectedHost {
				t.Errorf("Host = %v, want %v", issuerReq.Host, tt.expectedHost)
			}
			if issuerReq.Scheme != tt.expectedScheme {
				t.Errorf("Scheme = %v, want %v", issuerReq.Scheme, tt.expectedScheme)
			}
		})
	}
}

// ==================== IssuerRequestContext 测试 ====================

func TestIssuerRequestContext(t *testing.T) {
	ctx := context.Background()

	// 测试从空上下文获取
	_, err := IssuerRequestFromContext(ctx)
	if err != ErrContextNotFoundIssuerRequest {
		t.Errorf("Expected ErrContextNotFoundIssuerRequest, got %v", err)
	}

	// 测试设置和获取
	issuerReq := IssuerRequest{
		Host:   "tenant1.example.com",
		Scheme: "https",
	}
	ctx = NewIssuerRequestContext(ctx, issuerReq)

	got, err := IssuerRequestFromContext(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if got.Host != issuerReq.Host {
		t.Errorf("Host = %v, want %v", got.Host, issuerReq.Host)
	}
	if got.Scheme != issuerReq.Scheme {
		t.Errorf("Scheme = %v, want %v", got.Scheme, issuerReq.Scheme)
	}
}

// ==================== ServerOptions Issuer 测试 ====================

func TestServerOptionsGetIssuerRequest(t *testing.T) {
	// 测试默认提取函数
	opts := &ServerOptions{}
	req := httptest.NewRequest("GET", "http://default.example.com/", nil)
	req.Host = "default.example.com"

	issuerReq := opts.GetIssuerRequest(req)
	if issuerReq.Host != "default.example.com" {
		t.Errorf("Host = %v, want %v", issuerReq.Host, "default.example.com")
	}

	// 测试自定义提取函数
	opts.IssuerRequestFunc = func(r *http.Request) IssuerRequest {
		return IssuerRequest{
			Host:   r.Header.Get("X-Custom-Host"),
			Scheme: "https",
		}
	}
	req.Header.Set("X-Custom-Host", "custom.example.com")

	issuerReq = opts.GetIssuerRequest(req)
	if issuerReq.Host != "custom.example.com" {
		t.Errorf("Host = %v, want %v", issuerReq.Host, "custom.example.com")
	}
}

func TestServerOptionsGetIssuerFromContext(t *testing.T) {
	// 测试静态Issuer
	opts := &ServerOptions{
		Issuer: "https://static.example.com",
	}
	ctx := context.Background()

	issuer := opts.GetIssuerFromContext(ctx)
	if issuer != "https://static.example.com" {
		t.Errorf("Issuer = %v, want %v", issuer, "https://static.example.com")
	}

	// 测试动态IssuerFunc
	opts.IssuerFunc = func(ctx context.Context, req IssuerRequest) string {
		return req.Scheme + "://" + req.Host
	}

	// 无IssuerRequest在上下文中，应回退到静态Issuer
	issuer = opts.GetIssuerFromContext(ctx)
	if issuer != "https://static.example.com" {
		t.Errorf("Issuer = %v, want %v", issuer, "https://static.example.com")
	}

	// 有IssuerRequest在上下文中，应使用动态函数
	issuerReq := IssuerRequest{Host: "tenant1.example.com", Scheme: "https"}
	ctx = NewIssuerRequestContext(ctx, issuerReq)

	issuer = opts.GetIssuerFromContext(ctx)
	if issuer != "https://tenant1.example.com" {
		t.Errorf("Issuer = %v, want %v", issuer, "https://tenant1.example.com")
	}
}

// ==================== ParseHS256JwtClaimsTokenUnverified 测试 ====================

func TestParseHS256JwtClaimsTokenUnverified(t *testing.T) {
	// 先生成一个token用于测试
	claims := NewJwtClaims("https://tenant1.example.com", "test-client", "read write", "user123")
	token, err := NewHS256JwtClaimsToken(claims, testJwtKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// 测试无签名验证解析
	parsedClaims, err := ParseHS256JwtClaimsTokenUnverified(token)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if parsedClaims.Issuer != "https://tenant1.example.com" {
		t.Errorf("Issuer = %v, want %v", parsedClaims.Issuer, "https://tenant1.example.com")
	}
	if parsedClaims.Scope != "read write" {
		t.Errorf("Scope = %v, want %v", parsedClaims.Scope, "read write")
	}
	if parsedClaims.Subject != "user123" {
		t.Errorf("Subject = %v, want %v", parsedClaims.Subject, "user123")
	}
	if len(parsedClaims.Audience) != 1 || parsedClaims.Audience[0] != "test-client" {
		t.Errorf("Audience = %v, want [test-client]", parsedClaims.Audience)
	}
}

func TestParseHS256JwtClaimsTokenUnverified_InvalidToken(t *testing.T) {
	_, err := ParseHS256JwtClaimsTokenUnverified("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token, got nil")
	}
}

// ==================== MultiTenantAccessToken 测试 ====================

func TestNewMultiTenantAccessToken(t *testing.T) {
	tenantKeys := map[string][]byte{
		"https://tenant1.example.com": testTenant1Key,
		"https://tenant2.example.com": testTenant2Key,
	}

	accessToken := NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
		if key, ok := tenantKeys[issuer]; ok {
			return key
		}
		return testDefaultKey
	})

	ctx := context.Background()

	// 测试 tenant1 生成token
	token1, err := accessToken.Generate(ctx, "https://tenant1.example.com", "client1", "read", "user1", nil)
	if err != nil {
		t.Fatalf("Failed to generate token for tenant1: %v", err)
	}
	if token1.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}

	// 测试 tenant2 生成token
	token2, err := accessToken.Generate(ctx, "https://tenant2.example.com", "client2", "write", "user2", nil)
	if err != nil {
		t.Fatalf("Failed to generate token for tenant2: %v", err)
	}
	if token2.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}

	// 验证两个token的issuer不同
	claims1, err := accessToken.Parse(ctx, token1.AccessToken)
	if err != nil {
		t.Fatalf("Failed to parse token1: %v", err)
	}
	if claims1.Issuer != "https://tenant1.example.com" {
		t.Errorf("Token1 issuer = %v, want %v", claims1.Issuer, "https://tenant1.example.com")
	}

	claims2, err := accessToken.Parse(ctx, token2.AccessToken)
	if err != nil {
		t.Fatalf("Failed to parse token2: %v", err)
	}
	if claims2.Issuer != "https://tenant2.example.com" {
		t.Errorf("Token2 issuer = %v, want %v", claims2.Issuer, "https://tenant2.example.com")
	}
}

func TestMultiTenantAccessToken_Refresh(t *testing.T) {
	tenantKeys := map[string][]byte{
		"https://tenant1.example.com": testTenant1Key,
	}

	accessToken := NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
		if key, ok := tenantKeys[issuer]; ok {
			return key
		}
		return testDefaultKey
	})

	ctx := context.Background()

	// 生成初始token，使用 clientID 作为 openID 以便 refresh 验证通过
	// 这是因为 NewDefaultRefreshAccessToken 验证 tokenClaims.Subject == clientID
	clientID := "client1"
	token, err := accessToken.Generate(ctx, "https://tenant1.example.com", clientID, "read", clientID, nil)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// 刷新token
	refreshedToken, err := accessToken.Refresh(ctx, clientID, token.RefreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	if refreshedToken.AccessToken == "" {
		t.Error("Refreshed AccessToken should not be empty")
	}

	// 验证刷新后的token
	claims, err := accessToken.Parse(ctx, refreshedToken.AccessToken)
	if err != nil {
		t.Fatalf("Failed to parse refreshed token: %v", err)
	}
	if claims.Issuer != "https://tenant1.example.com" {
		t.Errorf("Refreshed token issuer = %v, want %v", claims.Issuer, "https://tenant1.example.com")
	}
}

func TestDefaultAccessToken_StaticKey(t *testing.T) {
	accessToken := NewDefaultAccessToken(testJwtKey)
	ctx := context.Background()

	// 生成token
	token, err := accessToken.Generate(ctx, "https://example.com", "client1", "read", "user1", nil)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// 解析token
	claims, err := accessToken.Parse(ctx, token.AccessToken)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}
	if claims.Issuer != "https://example.com" {
		t.Errorf("Issuer = %v, want %v", claims.Issuer, "https://example.com")
	}
}

// ==================== ServerOption 测试 ====================

func TestServerIssuerFuncOption(t *testing.T) {
	issuerFunc := func(ctx context.Context, req IssuerRequest) string {
		return req.Scheme + "://" + req.Host
	}

	opts := newServerOptions(ServerIssuerFunc(issuerFunc))

	if opts.IssuerFunc == nil {
		t.Error("IssuerFunc should be set")
	}

	// 测试函数行为
	issuerReq := IssuerRequest{Host: "test.example.com", Scheme: "https"}
	ctx := NewIssuerRequestContext(context.Background(), issuerReq)
	issuer := opts.GetIssuerFromContext(ctx)
	if issuer != "https://test.example.com" {
		t.Errorf("Issuer = %v, want %v", issuer, "https://test.example.com")
	}
}

func TestServerIssuerRequestFuncOption(t *testing.T) {
	customFunc := func(r *http.Request) IssuerRequest {
		return IssuerRequest{
			Host:   r.Header.Get("X-Custom"),
			Scheme: "https",
		}
	}

	opts := newServerOptions(ServerIssuerRequestFunc(customFunc))

	if opts.IssuerRequestFunc == nil {
		t.Error("IssuerRequestFunc should be set")
	}

	req := httptest.NewRequest("GET", "http://localhost/", nil)
	req.Header.Set("X-Custom", "custom.example.com")

	issuerReq := opts.GetIssuerRequest(req)
	if issuerReq.Host != "custom.example.com" {
		t.Errorf("Host = %v, want %v", issuerReq.Host, "custom.example.com")
	}
}

// ==================== 多租户端到端测试 ====================

func TestMultiTenantEndToEnd(t *testing.T) {
	// 模拟多租户场景的完整流程
	tenantKeys := map[string][]byte{
		"https://tenant1.example.com": testTenant1Key,
		"https://tenant2.example.com": testTenant2Key,
	}

	// 创建多租户AccessToken处理器
	accessToken := NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
		return tenantKeys[issuer]
	})

	// 模拟租户1的请求
	t.Run("Tenant1", func(t *testing.T) {
		ctx := context.Background()
		issuer := "https://tenant1.example.com"

		// 生成token
		token, err := accessToken.Generate(ctx, issuer, "client-a", "read write", "user-001", nil)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		// 验证token
		claims, err := accessToken.Parse(ctx, token.AccessToken)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}

		if claims.Issuer != issuer {
			t.Errorf("Issuer mismatch: got %v, want %v", claims.Issuer, issuer)
		}
		if claims.Scope != "read write" {
			t.Errorf("Scope mismatch: got %v, want %v", claims.Scope, "read write")
		}
	})

	// 模拟租户2的请求
	t.Run("Tenant2", func(t *testing.T) {
		ctx := context.Background()
		issuer := "https://tenant2.example.com"

		// 生成token
		token, err := accessToken.Generate(ctx, issuer, "client-b", "admin", "user-002", nil)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		// 验证token
		claims, err := accessToken.Parse(ctx, token.AccessToken)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}

		if claims.Issuer != issuer {
			t.Errorf("Issuer mismatch: got %v, want %v", claims.Issuer, issuer)
		}
	})

	// 测试使用错误密钥解析会失败
	t.Run("WrongKey", func(t *testing.T) {
		ctx := context.Background()

		// 使用tenant1的密钥生成token
		token, err := accessToken.Generate(ctx, "https://tenant1.example.com", "client", "read", "user", nil)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		// 创建一个使用错误密钥的解析器
		wrongKeyAccessToken := NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
			return testWrongKey
		})

		_, err = wrongKeyAccessToken.Parse(ctx, token.AccessToken)
		if err == nil {
			t.Error("Expected error when parsing with wrong key")
		}
	})
}
