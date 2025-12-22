package oauth2

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/nilorg/pkg/slice"
	sdkStrings "github.com/nilorg/sdk/strings"
)

// VerifyClientFunc 验证客户端委托
type VerifyClientFunc func(ctx context.Context, basic *ClientBasic) (err error)

// VerifyClientIDFunc 验证客户端ID委托
type VerifyClientIDFunc func(ctx context.Context, clientID string) (err error)

// VerifyRedirectURIFunc 验证RedirectURI委托
type VerifyRedirectURIFunc func(ctx context.Context, clientID, redirectURI string) (err error)

// GenerateCodeFunc 生成Code委托
// 支持 PKCE (RFC 7636)：codeChallenge 和 codeChallengeMethod 用于公开客户端安全增强
type GenerateCodeFunc func(ctx context.Context, clientID, openID, redirectURI string, scope []string, codeChallenge, codeChallengeMethod string) (code string, err error)

// VerifyCodeFunc 验证Code委托
type VerifyCodeFunc func(ctx context.Context, code, clientID, redirectURI string) (value *CodeValue, err error)

// VerifyPasswordFunc 验证账号密码委托
type VerifyPasswordFunc func(ctx context.Context, clientID, username, password string) (openID string, err error)

// VerifyScopeFunc 验证范围委托
type VerifyScopeFunc func(ctx context.Context, scope []string, clientID string) (err error)

// GenerateDeviceAuthorizationFunc 生成设备授权
type GenerateDeviceAuthorizationFunc func(ctx context.Context, issuer, verificationURI, clientID string, scope []string) (resp *DeviceAuthorizationResponse, err error)

// VerifyDeviceCodeFunc 验证DeviceCode委托
type VerifyDeviceCodeFunc func(ctx context.Context, deviceCode, clientID string) (value *DeviceCodeValue, err error)

// VerifyIntrospectionTokenFunc 验证IntrospectionToken委托
type VerifyIntrospectionTokenFunc func(ctx context.Context, token, clientID string, tokenTypeHint ...string) (resp *IntrospectionResponse, err error)

// TokenRevocationFunc Token撤销委托
// https://tools.ietf.org/html/rfc7009#section-2.2
type TokenRevocationFunc func(ctx context.Context, token, clientID string, tokenTypeHint ...string)

// CustomGrantTypeAuthenticationFunc 自定义GrantType身份验证委托
type CustomGrantTypeAuthenticationFunc func(ctx context.Context, client *ClientBasic, req *http.Request) (openID string, err error)

// VerifyGrantTypeFunc 验证授权类型委托
type VerifyGrantTypeFunc func(ctx context.Context, clientID, grantType string) (err error)

// GenerateAccessTokenFunc 生成AccessToken委托
type GenerateAccessTokenFunc func(ctx context.Context, issuer, clientID, scope, openID string, code *CodeValue) (token *TokenResponse, err error)

// NewDefaultGenerateAccessToken 创建默认生成AccessToken方法
func NewDefaultGenerateAccessToken(jwtVerifyKey []byte) GenerateAccessTokenFunc {
	return func(ctx context.Context, issuer, clientID, scope, openID string, codeVlue *CodeValue) (token *TokenResponse, err error) {
		scopeSplit := sdkStrings.Split(scope, " ")
		accessJwtClaims := NewJwtClaims(issuer, clientID, scope, openID)
		if codeVlue != nil {
			if len(scopeSplit) > 0 && !slice.IsEqual(scopeSplit, codeVlue.Scope) {
				accessJwtClaims = NewJwtClaims(issuer, clientID, strings.Join(codeVlue.Scope, " "), openID)
			}
		}
		var tokenStr string
		tokenStr, err = NewHS256JwtClaimsToken(accessJwtClaims, jwtVerifyKey)
		if err != nil {
			err = ErrServerError
			return
		}

		// refresh token 包含 clientID 用于刷新时验证客户端
		// refresh_token contains clientID for client verification during refresh
		refreshAccessJwtClaims := NewJwtClaims(issuer, clientID, ScopeRefreshToken, openID)
		refreshAccessJwtClaims.ID = tokenStr
		var refreshTokenStr string
		refreshTokenStr, err = NewHS256JwtClaimsToken(refreshAccessJwtClaims, jwtVerifyKey)
		if err != nil {
			err = ErrServerError
			return
		}
		token = &TokenResponse{
			AccessToken:  tokenStr,
			TokenType:    TokenTypeBearer,
			ExpiresIn:    accessJwtClaims.ExpiresAt,
			RefreshToken: refreshTokenStr,
			Scope:        scope,
		}
		return
	}
}

// ParseAccessTokenFunc 解析AccessToken为JwtClaims委托
type ParseAccessTokenFunc func(ctx context.Context, accessToken string) (claims *JwtClaims, err error)

// NewDefaultRefreshAccessToken 创建默认刷新AccessToken方法
// Create default refresh access token method
//
// 刷新令牌验证逻辑：
// 1. 验证 refresh_token 签名和格式
// 2. 验证 refresh_token 的 Audience (clientID) 与请求的 clientID 匹配
// 3. 验证 refresh_token 的 Scope 为 refresh_token
// 4. 验证原 access_token 的 Audience (clientID) 与请求的 clientID 匹配
//
// Refresh token validation logic:
// 1. Verify refresh_token signature and format
// 2. Verify refresh_token Audience (clientID) matches requesting clientID
// 3. Verify refresh_token Scope is refresh_token
// 4. Verify original access_token Audience (clientID) matches requesting clientID
func NewDefaultRefreshAccessToken(jwtVerifyKey []byte) RefreshAccessTokenFunc {
	return func(ctx context.Context, clientID, refreshToken string) (token *TokenResponse, err error) {
		var refreshTokenClaims *JwtClaims
		refreshTokenClaims, err = ParseHS256JwtClaimsToken(refreshToken, jwtVerifyKey)
		if err != nil {
			return
		}
		// 验证 refresh_token 的 Audience 是否包含当前客户端 (clientID 存储在 Audience 中)
		// Verify refresh_token Audience contains current client
		if !refreshTokenClaims.VerifyAudience([]string{clientID}, true) {
			err = ErrUnauthorizedClient
			return
		}
		if refreshTokenClaims.Scope != ScopeRefreshToken {
			err = ErrInvalidScope
			return
		}
		refreshTokenClaims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()

		var tokenClaims *JwtClaims
		tokenClaims, err = ParseHS256JwtClaimsToken(refreshTokenClaims.ID, jwtVerifyKey)
		if err != nil {
			return
		}
		// 验证原 access_token 的 Audience 是否包含当前客户端
		// Verify original access_token Audience contains current client
		if !tokenClaims.VerifyAudience([]string{clientID}, true) {
			err = ErrUnauthorizedClient
			return
		}
		tokenClaims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()

		var refreshTokenStr string
		refreshTokenStr, err = NewHS256JwtClaimsToken(refreshTokenClaims, jwtVerifyKey)
		if err != nil {
			return
		}
		var tokenStr string
		tokenStr, err = NewHS256JwtClaimsToken(tokenClaims, jwtVerifyKey)
		token = &TokenResponse{
			AccessToken:  tokenStr,
			RefreshToken: refreshTokenStr,
			TokenType:    TokenTypeBearer,
			ExpiresIn:    refreshTokenClaims.ExpiresAt,
			Scope:        tokenClaims.Scope,
		}
		return
	}
}

// RefreshAccessTokenFunc 刷新AccessToken委托
type RefreshAccessTokenFunc func(ctx context.Context, clientID, refreshToken string) (token *TokenResponse, err error)

// NewDefaultParseAccessToken 创建默认解析AccessToken方法
func NewDefaultParseAccessToken(jwtVerifyKey []byte) ParseAccessTokenFunc {
	return func(ctx context.Context, accessToken string) (claims *JwtClaims, err error) {
		return ParseHS256JwtClaimsToken(accessToken, jwtVerifyKey)
	}
}

// AccessTokener AccessToken接口
type AccessTokener interface {
	Generate(ctx context.Context, issuer, clientID, scope, openID string, code *CodeValue) (token *TokenResponse, err error)
	Refresh(ctx context.Context, clientID, refreshToken string) (token *TokenResponse, err error)
	Parse(ctx context.Context, accessToken string) (claims *JwtClaims, err error)
}

// JwtKeyFunc 动态获取JWT密钥的函数类型，用于SaaS多租户场景
// Dynamic JWT key function type for SaaS multi-tenant scenarios
// ctx 中包含 IssuerRequest 信息，可通过 IssuerRequestFromContext 获取
type JwtKeyFunc func(ctx context.Context, issuer string) []byte

type DefaultAccessToken struct {
	AccessTokener
	JwtVerifyKey []byte     // 静态密钥 / Static key
	JwtKeyFunc   JwtKeyFunc // 动态密钥函数，优先级高于静态密钥 / Dynamic key function, takes precedence over static key
}

// NewDefaultAccessToken 创建默认AccessToken处理器（静态密钥）
// Create default AccessToken handler with static key
func NewDefaultAccessToken(jwtVerifyKey []byte) *DefaultAccessToken {
	return &DefaultAccessToken{
		JwtVerifyKey: jwtVerifyKey,
	}
}

// NewMultiTenantAccessToken 创建多租户AccessToken处理器（动态密钥）
// Create multi-tenant AccessToken handler with dynamic key
// 示例 / Example:
//
//	NewMultiTenantAccessToken(func(ctx context.Context, issuer string) []byte {
//	    // 根据 issuer 从数据库/配置中获取对应租户的密钥
//	    // Get tenant's key from database/config based on issuer
//	    return getTenantJwtKey(issuer)
//	})
func NewMultiTenantAccessToken(jwtKeyFunc JwtKeyFunc) *DefaultAccessToken {
	return &DefaultAccessToken{
		JwtKeyFunc: jwtKeyFunc,
	}
}

// getKey 获取JWT密钥
func (d *DefaultAccessToken) getKey(ctx context.Context, issuer string) []byte {
	if d.JwtKeyFunc != nil {
		return d.JwtKeyFunc(ctx, issuer)
	}
	return d.JwtVerifyKey
}

// Generate 生成AccessToken
func (d *DefaultAccessToken) Generate(ctx context.Context, issuer, clientID, scope, openID string, code *CodeValue) (token *TokenResponse, err error) {
	jwtKey := d.getKey(ctx, issuer)
	return NewDefaultGenerateAccessToken(jwtKey)(ctx, issuer, clientID, scope, openID, code)
}

// Refresh 刷新AccessToken
func (d *DefaultAccessToken) Refresh(ctx context.Context, clientID, refreshToken string) (token *TokenResponse, err error) {
	// 刷新时需要先解析token获取issuer
	// When refreshing, need to parse token first to get issuer
	claims, parseErr := ParseHS256JwtClaimsTokenUnverified(refreshToken)
	if parseErr != nil {
		err = ErrInvalidGrant
		return
	}
	jwtKey := d.getKey(ctx, claims.Issuer)
	return NewDefaultRefreshAccessToken(jwtKey)(ctx, clientID, refreshToken)
}

// Parse 解析AccessToken
func (d *DefaultAccessToken) Parse(ctx context.Context, accessToken string) (claims *JwtClaims, err error) {
	// 解析时需要先获取issuer
	// When parsing, need to get issuer first
	claims, parseErr := ParseHS256JwtClaimsTokenUnverified(accessToken)
	if parseErr != nil {
		err = parseErr
		return
	}
	jwtKey := d.getKey(ctx, claims.Issuer)
	return NewDefaultParseAccessToken(jwtKey)(ctx, accessToken)
}
