package oauth2

// TokenResponse token response.
type TokenResponse struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type,omitempty"`
	ExpiresIn    int64       `json:"expires_in"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	Data         interface{} `json:"data,omitempty"`
	Scope        string      `json:"scope,omitempty"`
}

// ErrorResponse error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// CodeValue code值
type CodeValue struct {
	ClientID    string   `json:"client_id"`
	OpenID      string   `json:"open_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scope       []string `json:"scope"`
}

// ClientBasic 客户端基础
type ClientBasic struct {
	ID     string `json:"client_id"`
	Secret string `json:"client_secret"`
}

// GenerateAccessToken 生成AccessToken
func (client *ClientBasic) GenerateAccessToken(issuer, redirectURI, scope, openID string) (token *TokenResponse, err error) {
	claims := NewJwtClaims(issuer, client.ID, scope, redirectURI, openID)
	claims.Audience = redirectURI

	var tokenStr string
	tokenStr, err = NewAccessToken(claims, client.TokenVerifyKey())
	if err != nil {
		err = ErrServerError
	}
	var refreshTokenStr string
	refreshTokenStr, err = client.GenerateRefreshToken(issuer, tokenStr, redirectURI)
	if err != nil {
		err = ErrServerError
	}
	token = &TokenResponse{
		AccessToken:  tokenStr,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    claims.ExpiresAt,
		RefreshToken: refreshTokenStr,
		Scope:        scope,
	}
	return
}

// GenerateRefreshToken 生成刷新Token
func (client *ClientBasic) GenerateRefreshToken(issuer, accessToken, redirectURI string) (token string, err error) {

	claims := NewJwtClaims(issuer, client.ID, ScopeRefreshToken, redirectURI, "")
	claims.Id = accessToken

	return newJwtToken(claims, client.TokenVerifyKey())
}

// ParseAccessToken 解析AccessToken为JwtClaims
func (client *ClientBasic) ParseAccessToken(accessToken string) (claims *JwtClaims, err error) {
	claims, err = ParseAccessToken(accessToken, client.TokenVerifyKey())
	if err != nil {
		err = ErrServerError
	}
	if claims.Valid() != nil {
		err = ErrAccessDenied
	}
	return
}

// TokenVerifyKey ...
func (client *ClientBasic) TokenVerifyKey() []byte {
	return []byte(client.ID + client.Secret)
}
