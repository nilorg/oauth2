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
type GenerateCodeFunc func(ctx context.Context, clientID, openID, redirectURI string, scope []string) (code string, err error)

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

		refreshAccessJwtClaims := NewJwtClaims(issuer, clientID, ScopeRefreshToken, "")
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
func NewDefaultRefreshAccessToken(jwtVerifyKey []byte) RefreshAccessTokenFunc {
	return func(ctx context.Context, clientID, refreshToken string) (token *TokenResponse, err error) {
		var refreshTokenClaims *JwtClaims
		refreshTokenClaims, err = ParseHS256JwtClaimsToken(refreshToken, jwtVerifyKey)
		if err != nil {
			return
		}
		if refreshTokenClaims.Subject != clientID {
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
		if tokenClaims.Subject != clientID {
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

type DefaultAccessToken struct {
	AccessTokener
	JwtVerifyKey []byte
}

func NewDefaultAccessToken(jwtVerifyKey []byte) *DefaultAccessToken {
	return &DefaultAccessToken{
		JwtVerifyKey: jwtVerifyKey,
	}
}

// Generate 生成AccessToken
func (d *DefaultAccessToken) Generate(ctx context.Context, issuer, clientID, scope, openID string, code *CodeValue) (token *TokenResponse, err error) {
	return NewDefaultGenerateAccessToken(d.JwtVerifyKey)(ctx, issuer, clientID, scope, openID, code)
}

// Refresh 刷新AccessToken
func (d *DefaultAccessToken) Refresh(ctx context.Context, clientID, refreshToken string) (token *TokenResponse, err error) {
	return NewDefaultRefreshAccessToken(d.JwtVerifyKey)(ctx, clientID, refreshToken)
}

// Parse 解析AccessToken
func (d *DefaultAccessToken) Parse(ctx context.Context, accessToken string) (claims *JwtClaims, err error) {
	return NewDefaultParseAccessToken(d.JwtVerifyKey)(ctx, accessToken)
}
