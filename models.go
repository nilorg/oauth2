package oauth2

import "encoding/json"

// TokenResponse 令牌响应结构 / Token response structure
type TokenResponse struct {
	AccessToken  string      `json:"access_token"`            // 访问令牌 / Access token
	TokenType    string      `json:"token_type,omitempty"`    // 令牌类型 / Token type (e.g., Bearer)
	ExpiresIn    int64       `json:"expires_in"`              // 过期时间（秒） / Expiration time in seconds
	RefreshToken string      `json:"refresh_token,omitempty"` // 刷新令牌 / Refresh token
	Data         interface{} `json:"data,omitempty"`          // 自定义数据 / Custom data
	Scope        string      `json:"scope,omitempty"`         // 授权范围 / Authorized scope
	IDToken      string      `json:"id_token,omitempty"`      // ID令牌 / ID token (OpenID Connect)
}

// DeviceAuthorizationResponse 设备授权响应结构 / Device authorization response (RFC 8628)
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`                         // 设备码 / Device verification code
	UserCode                string `json:"user_code"`                           // 用户码 / User verification code
	VerificationURI         string `json:"verification_uri"`                    // 验证URI / Verification URI
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"` // 完整验证URI / Complete verification URI with user code
	ExpiresIn               int64  `json:"expires_in"`                          // 过期时间（秒） / Expiration time in seconds
	Interval                int    `json:"interval"`                            // 轮询间隔（秒） / Polling interval in seconds
}

// IntrospectionResponse 令牌内省响应结构 / Token introspection response (RFC 7662)
type IntrospectionResponse struct {
	Active   bool   `json:"active"`              // 令牌是否有效 / Whether the token is active
	ClientID string `json:"client_id,omitempty"` // 客户端ID / Client identifier
	Username string `json:"username,omitempty"`  // 用户名 / Resource owner username
	Scope    string `json:"scope,omitempty"`     // 授权范围 / Token scope
	Sub      string `json:"sub,omitempty"`       // 主体 / Subject (user identifier)
	Aud      string `json:"aud,omitempty"`       // 受众 / Audience
	Iss      int64  `json:"iss,omitempty"`       // 颁发者 / Issuer
	Exp      int64  `json:"exp,omitempty"`       // 过期时间 / Expiration time
}

// ErrorResponse 错误响应结构 / Error response structure
type ErrorResponse struct {
	Error string `json:"error"` // 错误码 / Error code
}

// CodeValue 授权码存储值 / Authorization code storage value
type CodeValue struct {
	ClientID    string   `json:"client_id"`    // 客户端ID / Client identifier
	OpenID      string   `json:"open_id"`      // 用户唯一标识 / User unique identifier
	RedirectURI string   `json:"redirect_uri"` // 重定向URI / Redirect URI
	Scope       []string `json:"scope"`        // 授权范围 / Authorized scopes
}

// MarshalBinary 序列化为JSON二进制 / Serialize to JSON binary
func (code *CodeValue) MarshalBinary() ([]byte, error) {
	return json.Marshal(code)
}

// UnmarshalBinary 从JSON二进制反序列化 / Deserialize from JSON binary
func (code *CodeValue) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, code)
}

// DeviceCodeValue 设备码存储值 / Device code storage value
type DeviceCodeValue struct {
	OpenID string   `json:"open_id"` // 用户唯一标识 / User unique identifier
	Scope  []string `json:"scope"`   // 授权范围 / Authorized scopes
}

// MarshalBinary 序列化为JSON二进制 / Serialize to JSON binary
func (code *DeviceCodeValue) MarshalBinary() ([]byte, error) {
	return json.Marshal(code)
}

// UnmarshalBinary 从JSON二进制反序列化 / Deserialize from JSON binary
func (code *DeviceCodeValue) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, code)
}

// ClientBasic 客户端基础信息 / Client basic credentials
type ClientBasic struct {
	ID     string `json:"client_id"`     // 客户端ID / Client identifier
	Secret string `json:"client_secret"` // 客户端密钥 / Client secret
}
