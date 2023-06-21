package oauth2

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Client oauth2 client
type Client struct {
	Log                         Logger
	httpClient                  *http.Client
	ServerBaseURL               string
	AuthorizationEndpoint       string
	TokenEndpoint               string
	IntrospectEndpoint          string
	DeviceAuthorizationEndpoint string
	TokenRevocationEndpoint     string
	ID                          string
	Secret                      string
}

// NewClient new oauth2 client
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

// AuthorizeAuthorizationCode ...
func (c *Client) AuthorizeAuthorizationCode(ctx context.Context, w http.ResponseWriter, redirectURI, scope, state string) (err error) {
	return c.authorize(ctx, w, CodeKey, redirectURI, scope, state)
}

// TokenAuthorizationCode ...
// TokenAuthorizationCode(code, redirectURI, state string)
func (c *Client) TokenAuthorizationCode(ctx context.Context, code, redirectURI, clientID string) (token *TokenResponse, err error) {
	values := url.Values{
		CodeKey:        []string{code},
		RedirectURIKey: []string{redirectURI},
		ClientIDKey:    []string{clientID},
	}
	return c.token(ctx, AuthorizationCodeKey, values)
}

// AuthorizeImplicit ...
func (c *Client) AuthorizeImplicit(ctx context.Context, w http.ResponseWriter, redirectURI, scope, state string) (err error) {
	return c.authorize(ctx, w, TokenKey, redirectURI, scope, state)
}

// DeviceAuthorization ...
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
	body, err = ioutil.ReadAll(resp.Body)
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

// TokenResourceOwnerPasswordCredentials ...
func (c *Client) TokenResourceOwnerPasswordCredentials(ctx context.Context, username, password string) (model *TokenResponse, err error) {
	values := url.Values{
		UsernameKey: []string{username},
		PasswordKey: []string{password},
	}
	return c.token(ctx, PasswordKey, values)
}

// TokenClientCredentials ...
func (c *Client) TokenClientCredentials(ctx context.Context, scope ...string) (model *TokenResponse, err error) {
	values := url.Values{}
	if len(scope) > 0 {
		values.Set(ScopeKey, scope[0])
	}
	return c.token(ctx, ClientCredentialsKey, values)
}

// RefreshToken ...
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (model *TokenResponse, err error) {
	values := url.Values{
		RefreshTokenKey: []string{refreshToken},
	}
	return c.token(ctx, RefreshTokenKey, values)
}

// TokenDeviceCode ...
func (c *Client) TokenDeviceCode(ctx context.Context, deviceCode string) (model *TokenResponse, err error) {
	values := url.Values{
		ClientIDKey:   []string{c.ID},
		DeviceCodeKey: []string{deviceCode},
	}
	return c.token(ctx, DeviceCodeKey, values)
}

// TokenIntrospect ...
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

// TokenRevocation token撤销
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
	body, err = ioutil.ReadAll(resp.Body)
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
