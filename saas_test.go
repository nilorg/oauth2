package oauth2

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// ==================== OpenID 上下文测试 ====================

func TestOpenIDContext(t *testing.T) {
	ctx := context.Background()

	// 测试从空上下文获取
	_, err := OpenIDFromContext(ctx)
	if err != ErrContextNotFoundOpenID {
		t.Errorf("Expected ErrContextNotFoundOpenID, got %v", err)
	}

	// 测试设置和获取
	openID := "user_123456"
	ctx = NewOpenIDContext(ctx, openID)

	got, err := OpenIDFromContext(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if got != openID {
		t.Errorf("OpenID = %v, want %v", got, openID)
	}
}

func TestOpenIDContext_EmptyString(t *testing.T) {
	ctx := context.Background()

	// 空字符串也是有效的 OpenID
	ctx = NewOpenIDContext(ctx, "")

	got, err := OpenIDFromContext(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("OpenID = %v, want empty string", got)
	}
}

// ==================== 错误路径测试 ====================

func TestDefaultAccessToken_ParseError(t *testing.T) {
	accessToken := NewDefaultAccessToken(testJwtKey)
	ctx := context.Background()

	// 测试解析无效 token
	_, err := accessToken.Parse(ctx, "invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}

	// 测试解析空 token
	_, err = accessToken.Parse(ctx, "")
	if err == nil {
		t.Error("Expected error for empty token")
	}
}

func TestDefaultAccessToken_RefreshError(t *testing.T) {
	accessToken := NewDefaultAccessToken(testJwtKey)
	ctx := context.Background()

	// 测试刷新无效 token
	_, err := accessToken.Refresh(ctx, "client1", "invalid-refresh-token")
	if err == nil {
		t.Error("Expected error for invalid refresh token")
	}

	// 测试刷新空 token
	_, err = accessToken.Refresh(ctx, "client1", "")
	if err == nil {
		t.Error("Expected error for empty refresh token")
	}
}

func TestMultiTenantAccessToken_ParseError(t *testing.T) {
	accessToken := NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
		return testTenant1Key
	})
	ctx := context.Background()

	// 测试解析无效 token
	_, err := accessToken.Parse(ctx, "invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}

	// 测试解析格式错误的 JWT
	_, err = accessToken.Parse(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature")
	if err == nil {
		t.Error("Expected error for malformed JWT")
	}
}

func TestMultiTenantAccessToken_RefreshError(t *testing.T) {
	accessToken := NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
		return testTenant1Key
	})
	ctx := context.Background()

	// 测试刷新无效 token
	_, err := accessToken.Refresh(ctx, "client1", "invalid-refresh-token")
	if err == nil {
		t.Error("Expected error for invalid refresh token")
	}
}

func TestMultiTenantAccessToken_RefreshWrongClient(t *testing.T) {
	accessToken := NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
		return testTenant1Key
	})
	ctx := context.Background()

	// 生成 token，clientID = openID
	token, err := accessToken.Generate(ctx, "https://tenant1.example.com", "client1", "read", "client1", nil)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// 使用错误的 clientID 刷新
	_, err = accessToken.Refresh(ctx, "wrong-client", token.RefreshToken)
	if err != ErrUnauthorizedClient {
		t.Errorf("Expected ErrUnauthorizedClient, got %v", err)
	}
}

// ==================== JWT Claims 验证测试 ====================

func TestJwtClaims_Valid(t *testing.T) {
	// 测试有效的 claims
	claims := NewJwtClaims("https://example.com", "client1", "read", "user1")
	err := claims.Valid()
	if err != nil {
		t.Errorf("Expected valid claims, got error: %v", err)
	}
}

func TestJwtClaims_Expired(t *testing.T) {
	claims := &JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			Issuer:    "https://example.com",
			Subject:   "user1",
			Audience:  []string{"client1"},
			ExpiresAt: 1000, // 1970年，已过期
			NotBefore: 0,
			IssuedAt:  0,
		},
		Scope: "read",
	}

	err := claims.Valid()
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestJwtClaims_VerifyScope(t *testing.T) {
	claims := &JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			Issuer:   "https://example.com",
			Subject:  "user1",
			Audience: []string{"client1"},
		},
		Scope: "read write admin",
	}

	tests := []struct {
		name     string
		scope    string
		required bool
		expected bool
	}{
		{"单个scope存在", "read", true, true},
		{"多个scope存在", "read write", true, true},
		{"scope不存在", "delete", true, false},
		{"部分scope不存在", "read delete", true, false},
		{"空scope非必需", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.VerifyScope(tt.scope, tt.required)
			if result != tt.expected {
				t.Errorf("VerifyScope(%q, %v) = %v, want %v", tt.scope, tt.required, result, tt.expected)
			}
		})
	}
}

func TestJwtClaims_VerifyAudience(t *testing.T) {
	claims := &JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			Audience: []string{"client1", "client2"},
		},
	}

	tests := []struct {
		name     string
		aud      []string
		required bool
		expected bool
	}{
		{"单个audience存在", []string{"client1"}, true, true},
		{"多个audience存在", []string{"client1", "client2"}, true, true},
		{"audience不存在", []string{"client3"}, true, false},
		{"空audience非必需", []string{}, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.VerifyAudience(tt.aud, tt.required)
			if result != tt.expected {
				t.Errorf("VerifyAudience(%v, %v) = %v, want %v", tt.aud, tt.required, result, tt.expected)
			}
		})
	}
}

func TestJwtClaims_VerifyIssuer(t *testing.T) {
	claims := &JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			Issuer: "https://example.com",
		},
	}

	tests := []struct {
		name     string
		issuer   string
		required bool
		expected bool
	}{
		{"issuer匹配", "https://example.com", true, true},
		{"issuer不匹配", "https://other.com", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.VerifyIssuer(tt.issuer, tt.required)
			if result != tt.expected {
				t.Errorf("VerifyIssuer(%q, %v) = %v, want %v", tt.issuer, tt.required, result, tt.expected)
			}
		})
	}

	// 测试空 issuer 的 claims
	emptyClaims := &JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			Issuer: "",
		},
	}
	// 当 claims.Issuer 为空且 required=false 时返回 true
	if !emptyClaims.VerifyIssuer("any", false) {
		t.Error("Empty issuer with required=false should return true")
	}
	// 当 claims.Issuer 为空且 required=true 时返回 false
	if emptyClaims.VerifyIssuer("any", true) {
		t.Error("Empty issuer with required=true should return false")
	}
}

func TestJwtClaims_VerifyExpiresAt(t *testing.T) {
	claims := &JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			ExpiresAt: 2000000000, // 2033年
		},
	}

	tests := []struct {
		name     string
		cmp      int64
		required bool
		expected bool
	}{
		{"未过期", 1700000000, true, true},
		{"已过期", 2100000000, true, false},
		{"刚好过期", 2000000000, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.VerifyExpiresAt(tt.cmp, tt.required)
			if result != tt.expected {
				t.Errorf("VerifyExpiresAt(%d, %v) = %v, want %v", tt.cmp, tt.required, result, tt.expected)
			}
		})
	}
}

func TestJwtClaims_VerifyNotBefore(t *testing.T) {
	claims := &JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			NotBefore: 1700000000, // 2023年
		},
	}

	tests := []struct {
		name     string
		cmp      int64
		required bool
		expected bool
	}{
		{"已生效", 1800000000, true, true},
		{"未生效", 1600000000, true, false},
		{"刚好生效", 1700000000, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.VerifyNotBefore(tt.cmp, tt.required)
			if result != tt.expected {
				t.Errorf("VerifyNotBefore(%d, %v) = %v, want %v", tt.cmp, tt.required, result, tt.expected)
			}
		})
	}
}

func TestJwtClaims_VerifyIssuedAt(t *testing.T) {
	claims := &JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			IssuedAt: 1700000000, // 2023年
		},
	}

	tests := []struct {
		name     string
		cmp      int64
		required bool
		expected bool
	}{
		{"颁发后使用", 1800000000, true, true},
		{"颁发前使用", 1600000000, true, false},
		{"刚好颁发", 1700000000, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.VerifyIssuedAt(tt.cmp, tt.required)
			if result != tt.expected {
				t.Errorf("VerifyIssuedAt(%d, %v) = %v, want %v", tt.cmp, tt.required, result, tt.expected)
			}
		})
	}
}

// ==================== ServerOption 测试补充 ====================

func TestServerLogger(t *testing.T) {
	logger := &DefaultLogger{}
	opts := newServerOptions(ServerLogger(logger))

	if opts.Log != logger {
		t.Error("Logger should be set")
	}
}

func TestServerIssuer(t *testing.T) {
	opts := newServerOptions(ServerIssuer("https://auth.example.com"))

	if opts.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %v, want %v", opts.Issuer, "https://auth.example.com")
	}
}

func TestServerDeviceAuthorizationEndpointEnabled(t *testing.T) {
	opts := newServerOptions(ServerDeviceAuthorizationEndpointEnabled(true))

	if !opts.DeviceAuthorizationEndpointEnabled {
		t.Error("DeviceAuthorizationEndpointEnabled should be true")
	}
}

func TestServerDeviceVerificationURI(t *testing.T) {
	opts := newServerOptions(ServerDeviceVerificationURI("/verify"))

	if opts.DeviceVerificationURI != "/verify" {
		t.Errorf("DeviceVerificationURI = %v, want %v", opts.DeviceVerificationURI, "/verify")
	}
}

func TestServerIntrospectEndpointEnabled(t *testing.T) {
	opts := newServerOptions(ServerIntrospectEndpointEnabled(true))

	if !opts.IntrospectEndpointEnabled {
		t.Error("IntrospectEndpointEnabled should be true")
	}
}

func TestServerTokenRevocationEnabled(t *testing.T) {
	opts := newServerOptions(ServerTokenRevocationEnabled(true))

	if !opts.TokenRevocationEnabled {
		t.Error("TokenRevocationEnabled should be true")
	}
}

func TestServerCustomGrantTypeEnabled(t *testing.T) {
	opts := newServerOptions(ServerCustomGrantTypeEnabled(true))

	if !opts.CustomGrantTypeEnabled {
		t.Error("CustomGrantTypeEnabled should be true")
	}
}

func TestServerCustomGrantTypeAuthentication(t *testing.T) {
	customAuth := map[string]CustomGrantTypeAuthenticationFunc{
		"custom_grant": func(ctx context.Context, client *ClientBasic, req *http.Request) (string, error) {
			return "user123", nil
		},
	}

	opts := newServerOptions(ServerCustomGrantTypeAuthentication(customAuth))

	if opts.CustomGrantTypeAuthentication == nil {
		t.Error("CustomGrantTypeAuthentication should be set")
	}
	if _, ok := opts.CustomGrantTypeAuthentication["custom_grant"]; !ok {
		t.Error("custom_grant should be in CustomGrantTypeAuthentication")
	}
}

// ==================== 组合配置测试 ====================

func TestServerOptions_CombinedOptions(t *testing.T) {
	opts := newServerOptions(
		ServerIssuer("https://default.example.com"),
		ServerIssuerFunc(func(ctx context.Context, req IssuerRequest) string {
			return req.Scheme + "://" + req.Host
		}),
		ServerIssuerRequestFunc(ProxyIssuerRequestFunc),
		ServerDeviceAuthorizationEndpointEnabled(true),
		ServerIntrospectEndpointEnabled(true),
		ServerTokenRevocationEnabled(true),
	)

	if opts.Issuer != "https://default.example.com" {
		t.Error("Issuer should be set")
	}
	if opts.IssuerFunc == nil {
		t.Error("IssuerFunc should be set")
	}
	if opts.IssuerRequestFunc == nil {
		t.Error("IssuerRequestFunc should be set")
	}
	if !opts.DeviceAuthorizationEndpointEnabled {
		t.Error("DeviceAuthorizationEndpointEnabled should be true")
	}
	if !opts.IntrospectEndpointEnabled {
		t.Error("IntrospectEndpointEnabled should be true")
	}
	if !opts.TokenRevocationEnabled {
		t.Error("TokenRevocationEnabled should be true")
	}
}

// ==================== NewJwtClaims 测试 ====================

func TestNewJwtClaims(t *testing.T) {
	claims := NewJwtClaims("https://issuer.com", "client123", "read write", "user456")

	if claims.Issuer != "https://issuer.com" {
		t.Errorf("Issuer = %v, want %v", claims.Issuer, "https://issuer.com")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "client123" {
		t.Errorf("Audience = %v, want [client123]", claims.Audience)
	}
	if claims.Scope != "read write" {
		t.Errorf("Scope = %v, want %v", claims.Scope, "read write")
	}
	if claims.Subject != "user456" {
		t.Errorf("Subject = %v, want %v", claims.Subject, "user456")
	}
	if claims.ExpiresAt == 0 {
		t.Error("ExpiresAt should not be 0")
	}
	if claims.NotBefore == 0 {
		t.Error("NotBefore should not be 0")
	}
	if claims.IssuedAt == 0 {
		t.Error("IssuedAt should not be 0")
	}
}

// ==================== TokenResponse 测试 ====================

func TestTokenResponse_Fields(t *testing.T) {
	accessToken := NewDefaultAccessToken(testJwtKey)
	ctx := context.Background()

	token, err := accessToken.Generate(ctx, "https://example.com", "client1", "read write", "user1", nil)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if token.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}
	if token.TokenType != TokenTypeBearer {
		t.Errorf("TokenType = %v, want %v", token.TokenType, TokenTypeBearer)
	}
	if token.ExpiresIn == 0 {
		t.Error("ExpiresIn should not be 0")
	}
	if token.Scope != "read write" {
		t.Errorf("Scope = %v, want %v", token.Scope, "read write")
	}
}

// ==================== JWT Token 函数测试 ====================

func TestNewJwtToken(t *testing.T) {
	claims := NewJwtClaims("https://issuer.com", "client1", "read", "user1")

	token, err := NewJwtToken(claims, "HS256", testJwtKey)
	if err != nil {
		t.Fatalf("NewJwtToken() error = %v", err)
	}
	if token == "" {
		t.Error("NewJwtToken() returned empty token")
	}
}

func TestNewJwtClaimsToken(t *testing.T) {
	claims := NewJwtClaims("https://issuer.com", "client1", "read", "user1")

	token, err := NewJwtClaimsToken(claims, "HS256", testJwtKey)
	if err != nil {
		t.Fatalf("NewJwtClaimsToken() error = %v", err)
	}
	if token == "" {
		t.Error("NewJwtClaimsToken() returned empty token")
	}

	// 验证可以解析
	parsed, err := ParseJwtClaimsToken(token, "HS256", testJwtKey)
	if err != nil {
		t.Fatalf("ParseJwtClaimsToken() error = %v", err)
	}
	if parsed.Issuer != "https://issuer.com" {
		t.Errorf("Parsed Issuer = %v, want %v", parsed.Issuer, "https://issuer.com")
	}
}

func TestNewJwtStandardClaimsToken(t *testing.T) {
	claims := &JwtStandardClaims{
		Issuer:   "https://issuer.com",
		Subject:  "user1",
		Audience: []string{"client1"},
	}

	token, err := NewJwtStandardClaimsToken(claims, "HS256", testJwtKey)
	if err != nil {
		t.Fatalf("NewJwtStandardClaimsToken() error = %v", err)
	}
	if token == "" {
		t.Error("NewJwtStandardClaimsToken() returned empty token")
	}

	// 验证可以解析
	parsed, err := ParseJwtStandardClaimsToken(token, "HS256", testJwtKey)
	if err != nil {
		t.Fatalf("ParseJwtStandardClaimsToken() error = %v", err)
	}
	if parsed.Issuer != "https://issuer.com" {
		t.Errorf("Parsed Issuer = %v, want %v", parsed.Issuer, "https://issuer.com")
	}
}

func TestParseJwtStandardClaimsToken(t *testing.T) {
	claims := &JwtStandardClaims{
		Issuer:   "https://test.com",
		Subject:  "subject123",
		Audience: []string{"aud1", "aud2"},
	}

	token, err := NewJwtStandardClaimsToken(claims, "HS256", testJwtKey)
	if err != nil {
		t.Fatalf("NewJwtStandardClaimsToken() error = %v", err)
	}

	parsed, err := ParseJwtStandardClaimsToken(token, "HS256", testJwtKey)
	if err != nil {
		t.Fatalf("ParseJwtStandardClaimsToken() error = %v", err)
	}

	if parsed.Subject != "subject123" {
		t.Errorf("Subject = %v, want %v", parsed.Subject, "subject123")
	}
	if len(parsed.Audience) != 2 {
		t.Errorf("Audience length = %v, want 2", len(parsed.Audience))
	}
}

func TestParseJwtClaimsToken_InvalidToken(t *testing.T) {
	_, err := ParseJwtClaimsToken("invalid.token.here", "HS256", testJwtKey)
	if err == nil {
		t.Error("ParseJwtClaimsToken() should return error for invalid token")
	}
}

func TestParseJwtClaimsToken_WrongKey(t *testing.T) {
	claims := NewJwtClaims("https://issuer.com", "client1", "read", "user1")
	token, _ := NewJwtClaimsToken(claims, "HS256", testJwtKey)

	_, err := ParseJwtClaimsToken(token, "HS256", testWrongKey)
	if err == nil {
		t.Error("ParseJwtClaimsToken() should return error for wrong key")
	}
}

// ==================== JwtClaims.Valid 边界测试 ====================

func TestJwtClaims_Valid_AllConditions(t *testing.T) {
	tests := []struct {
		name      string
		claims    *JwtClaims
		wantValid bool
	}{
		{
			name: "所有条件都满足",
			claims: &JwtClaims{
				JwtStandardClaims: JwtStandardClaims{
					Issuer:    "https://issuer.com",
					Audience:  []string{"client1"},
					ExpiresAt: time.Now().Add(3600 * time.Second).Unix(),
					NotBefore: time.Now().Add(-60 * time.Second).Unix(),
					IssuedAt:  time.Now().Add(-60 * time.Second).Unix(),
				},
				Scope: "read",
			},
			wantValid: true,
		},
		{
			name: "已过期",
			claims: &JwtClaims{
				JwtStandardClaims: JwtStandardClaims{
					Issuer:    "https://issuer.com",
					Audience:  []string{"client1"},
					ExpiresAt: time.Now().Add(-3600 * time.Second).Unix(), // 已过期
				},
				Scope: "read",
			},
			wantValid: false,
		},
		{
			name: "尚未生效",
			claims: &JwtClaims{
				JwtStandardClaims: JwtStandardClaims{
					Issuer:    "https://issuer.com",
					Audience:  []string{"client1"},
					ExpiresAt: time.Now().Add(3600 * time.Second).Unix(),
					NotBefore: time.Now().Add(3600 * time.Second).Unix(), // 未来才生效
				},
				Scope: "read",
			},
			wantValid: false,
		},
		{
			name: "IssuedAt在未来",
			claims: &JwtClaims{
				JwtStandardClaims: JwtStandardClaims{
					Issuer:    "https://issuer.com",
					Audience:  []string{"client1"},
					ExpiresAt: time.Now().Add(3600 * time.Second).Unix(),
					IssuedAt:  time.Now().Add(3600 * time.Second).Unix(), // 未来颁发
				},
				Scope: "read",
			},
			wantValid: false,
		},
		{
			// Valid() 只验证时间，不验证 Issuer/Audience/Scope
			name: "缺少Issuer仍然有效(时间验证通过)",
			claims: &JwtClaims{
				JwtStandardClaims: JwtStandardClaims{
					Issuer:    "",
					Audience:  []string{"client1"},
					ExpiresAt: time.Now().Add(3600 * time.Second).Unix(),
				},
				Scope: "read",
			},
			wantValid: true, // Valid() 只验证时间相关
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Valid()
			isValid := err == nil
			if isValid != tt.wantValid {
				t.Errorf("Valid() = %v, want %v, err = %v", isValid, tt.wantValid, err)
			}
		})
	}
}
