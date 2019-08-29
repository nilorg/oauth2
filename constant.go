package oauth2

import "time"

const (
	contentTypeJson    = "application/json;charset=UTF-8"
	AccessTokenExpire  = time.Second * 3600
	RefreshTokenExpire = AccessTokenExpire / 2
	TokenTypeBearer    = "Bearer"
	ScopeRefreshToken  = "refresh_token"
	DefaultJwtIssuer   = "github.com/nilorg/oauth2"
)
