package oauth2

import (
	"time"
)

// VerifyClientFunc 验证客户端委托
type VerifyClientFunc func(basic *ClientBasic) (err error)

// VerifyRedirectURIFunc 验证RedirectURI委托
type VerifyRedirectURIFunc func(clientID, redirectURI string) (err error)

// GenerateCodeFunc 生成Code委托
type GenerateCodeFunc func(clientID, openID, redirectURI string, scope []string) (code string, err error)

// VerifyCodeFunc 验证Code委托
type VerifyCodeFunc func(code, clientID, redirectURI string) (value *CodeValue, err error)

// VerifyPasswordFunc 验证账号密码委托
type VerifyPasswordFunc func(username, password string) (openID string, err error)

// VerifyScopeFunc 验证范围委托
type VerifyScopeFunc func(scope []string) (err error)

// GenerateAccessTokenFunc 生成AccessToken委托
type GenerateAccessTokenFunc func(issuer, clientID, scope, openID string) (token *TokenResponse, err error)

// ParseAccessTokenFunc 解析AccessToken为JwtClaims委托
type ParseAccessTokenFunc func(accessToken string) (claims *JwtClaims, err error)

// RefreshAccessTokenFunc 刷新AccessToken委托
type RefreshAccessTokenFunc func(clientID, refreshToken string) (token *TokenResponse, err error)

// NewDefaultGenerateAccessToken 创建默认生成AccessToken方法
func NewDefaultGenerateAccessToken(jwtVerifyKey []byte) GenerateAccessTokenFunc {
	return func(issuer, clientID, scope, openID string) (token *TokenResponse, err error) {
		accessJwtClaims := NewJwtClaims(issuer, clientID, scope, openID)
		var tokenStr string
		tokenStr, err = NewAccessToken(accessJwtClaims, jwtVerifyKey)
		if err != nil {
			err = ErrServerError
		}

		refreshAccessJwtClaims := NewJwtClaims(issuer, clientID, ScopeRefreshToken, "")
		refreshAccessJwtClaims.Id = tokenStr
		var refreshTokenStr string
		refreshTokenStr, err = newJwtToken(accessJwtClaims, jwtVerifyKey)
		if err != nil {
			err = ErrServerError
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

// NewDefaultRefreshAccessToken 创建默认刷新AccessToken方法
func NewDefaultRefreshAccessToken(jwtVerifyKey []byte) RefreshAccessTokenFunc {
	return func(clientID, refreshToken string) (token *TokenResponse, err error) {
		refreshTokenClaims := &JwtClaims{}
		refreshTokenClaims, err = ParseAccessToken(refreshToken, jwtVerifyKey)
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
		tokenClaims, err = ParseAccessToken(refreshTokenClaims.Id, jwtVerifyKey)
		if err != nil {
			return
		}
		if tokenClaims.Subject != clientID {
			err = ErrUnauthorizedClient
			return
		}
		tokenClaims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()

		var refreshTokenStr string
		refreshTokenStr, err = NewAccessToken(refreshTokenClaims, jwtVerifyKey)
		if err != nil {
			return
		}
		var tokenStr string
		tokenStr, err = NewAccessToken(tokenClaims, jwtVerifyKey)
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

// NewDefaultParseAccessToken 创建默认解析AccessToken方法
func NewDefaultParseAccessToken(jwtVerifyKey []byte) ParseAccessTokenFunc {
	return func(accessToken string) (claims *JwtClaims, err error) {
		return ParseAccessToken(accessToken, jwtVerifyKey)
	}
}
