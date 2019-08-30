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
	UserID      string   `json:"user_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scope       []string `json:"scope"`
}

// ClientBasic 客户端基础
type ClientBasic struct {
	ID     string `json:"client_id"`
	Secret string `json:"client_secret"`
}

// GenerateAccessToken 生成AccessToken
func (client *ClientBasic) GenerateAccessToken(issuer, redirectURI, scope, openID string) (token string, err error) {
	claims := NewJwtClaims(issuer, client.ID, scope, redirectURI, openID)
	claims.Audience = redirectURI
	token, err = NewAccessToken(claims, []byte(client.ID+client.Secret))
	if err != nil {
		err = ErrServerError
	}
	return
}

// GenerateRefreshToken 生成刷新Token
func (client *ClientBasic) GenerateRefreshToken(issuer, accessToken string) (token string, err error) {
	claims := NewJwtClaims(issuer, client.ID, ScopeRefreshToken, "", "")
	claims.Id = accessToken
	return newJwtToken(claims, []byte(client.ID+client.Secret))
}

// ParseAccessToken 解析AccessToken为JwtClaims
func (client *ClientBasic) ParseAccessToken(accessToken string) (claims *JwtClaims, err error) {
	claims, err = ParseAccessToken(accessToken, []byte(client.ID+client.Secret))
	if err != nil {
		err = ErrServerError
	}
	if claims.Valid() != nil {
		err = ErrAccessDenied
	}
	return
}
