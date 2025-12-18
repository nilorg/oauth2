package oauth2

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client OAuth2客户端 / OAuth2 client for making authorization requests
type Client struct {
	Log                         Logger       // 日志记录器 / Logger instance
	httpClient                  *http.Client // HTTP客户端 / HTTP client for requests
	ServerBaseURL               string       // 服务器基础URL / OAuth2 server base URL
	AuthorizationEndpoint       string       // 授权端点 / Authorization endpoint path
	TokenEndpoint               string       // 令牌端点 / Token endpoint path
	IntrospectEndpoint          string       // 内省端点 / Introspection endpoint path
	DeviceAuthorizationEndpoint string       // 设备授权端点 / Device authorization endpoint path
	TokenRevocationEndpoint     string       // 令牌撤销端点 / Token revocation endpoint path
	ID                          string       // 客户端ID / Client identifier
	Secret                      string       // 客户端密钥 / Client secret
}

// NewClient 创建OAuth2客户端 / Create a new OAuth2 client
// serverBaseURL: 服务器基础URL / OAuth2 server base URL
// id: 客户端ID / Client identifier
// secret: 客户端密钥 / Client secret
func NewClient(serverBaseURL, id, secret string) *Client {
	httpclient := &http.Client{}
	httpclient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		Log:                         &DefaultLogger{},
		httpClient:                  httpclient,
		ServerBaseURL:               serverBaseURL,
		AuthorizationEndpoint:       "/authorize",
		TokenEndpoint:               "/token",
		DeviceAuthorizationEndpoint: "/device_authorization",
		IntrospectEndpoint:          "/introspect",
		ID:                          id,
		Secret:                      secret,
	}
}

func (c *Client) authorize(ctx context.Context, w http.ResponseWriter, responseType, redirectURI, scope, state string) (err error) {
	var uri *url.URL
	uri, err = url.Parse(c.ServerBaseURL + c.AuthorizationEndpoint)
	if err != nil {
		return
	}
	query := uri.Query()
	query.Set(ResponseTypeKey, responseType)
	query.Set(ClientIDKey, c.ID)
	query.Set(RedirectURIKey, redirectURI)
	query.Set(ScopeKey, scope)
	query.Set(StateKey, state)
	uri.RawQuery = query.Encode()
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return
	}
	var resp *http.Response
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return
	}
	w.Header().Set("Location", resp.Header.Get("Location"))
	w.WriteHeader(resp.StatusCode)
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return
}

// AuthorizeAuthorizationCode 授权码模式授权请求 / Authorization code grant authorization request
// redirectURI: 重定向URI / Redirect URI after authorization
// scope: 授权范围 / Requested scope
// state: 状态码，用于防止CSRF攻击 / State parameter for CSRF protection
func (c *Client) AuthorizeAuthorizationCode(ctx context.Context, w http.ResponseWriter, redirectURI, scope, state string) (err error) {
	return c.authorize(ctx, w, CodeKey, redirectURI, scope, state)
}

// TokenAuthorizationCode 授权码模式获取令牌 / Exchange authorization code for access token
// code: 授权码 / Authorization code received from authorization server
// redirectURI: 重定向URI / Redirect URI used in authorization request
// clientID: 客户端ID / Client identifier
func (c *Client) TokenAuthorizationCode(ctx context.Context, code, redirectURI, clientID string) (token *TokenResponse, err error) {
	values := url.Values{
		CodeKey:        []string{code},
		RedirectURIKey: []string{redirectURI},
		ClientIDKey:    []string{clientID},
	}
	return c.token(ctx, AuthorizationCodeKey, values)
}

// AuthorizeImplicit 隐式授权模式授权请求 / Implicit grant authorization request
// redirectURI: 重定向URI / Redirect URI after authorization
// scope: 授权范围 / Requested scope
// state: 状态码，用于防止CSRF攻击 / State parameter for CSRF protection
func (c *Client) AuthorizeImplicit(ctx context.Context, w http.ResponseWriter, redirectURI, scope, state string) (err error) {
	return c.authorize(ctx, w, TokenKey, redirectURI, scope, state)
}

// DeviceAuthorization 设备授权请求 / Device authorization request (RFC 8628)
// scope: 授权范围 / Requested scope
func (c *Client) DeviceAuthorization(ctx context.Context, w http.ResponseWriter, scope string) (err error) {
	var uri *url.URL
	uri, err = url.Parse(c.ServerBaseURL + c.DeviceAuthorizationEndpoint)
	if err != nil {
		return
	}
	query := uri.Query()
	query.Set(ClientIDKey, c.ID)
	query.Set(ScopeKey, scope)
	uri.RawQuery = query.Encode()
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return
	}
	var resp *http.Response
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return
	}
	w.WriteHeader(resp.StatusCode)
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return
}

func (c *Client) Token(ctx context.Context, grantType string, values url.Values) (token *TokenResponse, err error) {
	return c.token(ctx, grantType, values)
}

func (c *Client) token(ctx context.Context, grantType string, values url.Values) (token *TokenResponse, err error) {
	var uri *url.URL
	uri, err = url.Parse(c.ServerBaseURL + c.TokenEndpoint)
	if err != nil {
		return
	}
	if values == nil {
		values = url.Values{
			GrantTypeKey: []string{grantType},
		}
	} else {
		values.Set(GrantTypeKey, grantType)
	}
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// explain: https://tools.ietf.org/html/rfc8628#section-3.4
	if grantType != DeviceCodeKey && grantType != UrnIetfParamsOAuthGrantTypeDeviceCodeKey {
		req.SetBasicAuth(c.ID, c.Secret)
	}

	var resp *http.Response
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var body []byte
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), ErrorKey) {
		errModel := ErrorResponse{}
		err = json.Unmarshal(body, &errModel)
		if err != nil {
			return
		}
		err = Errors[errModel.Error]
	} else {
		token = &TokenResponse{}
		err = json.Unmarshal(body, token)
	}
	return
}

// TokenResourceOwnerPasswordCredentials 密码模式获取令牌 / Resource owner password credentials grant
// username: 用户名 / Resource owner username
// password: 密码 / Resource owner password
func (c *Client) TokenResourceOwnerPasswordCredentials(ctx context.Context, username, password string) (model *TokenResponse, err error) {
	values := url.Values{
		UsernameKey: []string{username},
		PasswordKey: []string{password},
	}
	return c.token(ctx, PasswordKey, values)
}

// TokenClientCredentials 客户端凭证模式获取令牌 / Client credentials grant
// scope: 授权范围（可选） / Requested scope (optional)
func (c *Client) TokenClientCredentials(ctx context.Context, scope ...string) (model *TokenResponse, err error) {
	values := url.Values{}
	if len(scope) > 0 {
		values.Set(ScopeKey, scope[0])
	}
	return c.token(ctx, ClientCredentialsKey, values)
}

// RefreshToken 刷新访问令牌 / Refresh access token using refresh token
// refreshToken: 刷新令牌 / Refresh token
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (model *TokenResponse, err error) {
	values := url.Values{
		RefreshTokenKey: []string{refreshToken},
	}
	return c.token(ctx, RefreshTokenKey, values)
}

// TokenDeviceCode 设备码模式获取令牌 / Exchange device code for access token (RFC 8628)
// deviceCode: 设备码 / Device code received from device authorization
func (c *Client) TokenDeviceCode(ctx context.Context, deviceCode string) (model *TokenResponse, err error) {
	values := url.Values{
		ClientIDKey:   []string{c.ID},
		DeviceCodeKey: []string{deviceCode},
	}
	return c.token(ctx, DeviceCodeKey, values)
}

// TokenIntrospect 令牌内省 / Token introspection (RFC 7662)
// token: 要检查的令牌 / Token to introspect
// tokenTypeHint: 令牌类型提示（可选） / Token type hint (optional): access_token or refresh_token
func (c *Client) TokenIntrospect(ctx context.Context, token string, tokenTypeHint ...string) (introspection *IntrospectionResponse, err error) {
	values := url.Values{
		TokenKey: []string{token},
	}
	if len(tokenTypeHint) > 0 {
		if tokenTypeHint[0] != AccessTokenKey && tokenTypeHint[0] != RefreshTokenKey {
			err = ErrUnsupportedTokenType
			return
		}
		values.Set(TokenTypeHintKey, tokenTypeHint[0])
	}
	introspection = &IntrospectionResponse{}
	err = c.do(ctx, c.IntrospectEndpoint, values, introspection)
	return
}

// TokenRevocation 令牌撤销 / Token revocation (RFC 7009)
// token: 要撤销的令牌 / Token to revoke
// tokenTypeHint: 令牌类型提示（可选） / Token type hint (optional): access_token or refresh_token
func (c *Client) TokenRevocation(ctx context.Context, token string, tokenTypeHint ...string) (introspection *IntrospectionResponse, err error) {
	values := url.Values{
		TokenKey: []string{token},
	}
	if len(tokenTypeHint) > 0 {
		if tokenTypeHint[0] != AccessTokenKey && tokenTypeHint[0] != RefreshTokenKey {
			err = ErrUnsupportedTokenType
			return
		}
		values.Set(TokenTypeHintKey, tokenTypeHint[0])
	}
	err = c.do(ctx, c.TokenRevocationEndpoint, values, nil)
	return
}

func (c *Client) do(ctx context.Context, path string, values url.Values, v interface{}) (err error) {
	var uri *url.URL
	uri, err = url.Parse(c.ServerBaseURL + path)
	if err != nil {
		return
	}
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ID, c.Secret)
	var resp *http.Response
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var body []byte
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), ErrorKey) {
		errModel := ErrorResponse{}
		err = json.Unmarshal(body, &errModel)
		if err != nil {
			return
		}
		err = Errors[errModel.Error]
	} else {
		if v != nil {
			err = json.Unmarshal(body, v)
		}
	}
	return
}
