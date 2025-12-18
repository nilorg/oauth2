package oauth2

import "time"

const (
	// contentTypeJSON JSON内容类型 / JSON content type for HTTP responses
	contentTypeJSON = "application/json"
	// AccessTokenExpire 访问令牌过期时间（1小时） / Access token expiration time (1 hour)
	AccessTokenExpire = time.Second * 3600
	// RefreshTokenExpire 刷新令牌过期时间（30分钟） / Refresh token expiration time (30 minutes)
	RefreshTokenExpire = AccessTokenExpire / 2
	// TokenTypeBearer Bearer令牌类型 / Bearer token type
	TokenTypeBearer = "Bearer"
	// ScopeRefreshToken 刷新令牌的scope / Scope for refresh token
	ScopeRefreshToken = "refresh_token"
	// DefaultJwtIssuer 默认JWT颁发者 / Default JWT issuer
	DefaultJwtIssuer = "github.com/nilorg/oauth2"
)
