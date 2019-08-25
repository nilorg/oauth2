package oauth2

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	Log                   Logger
	httpClient            *http.Client
	ServerBaseUrl         string
	AuthorizationEndpoint string
	TokenEndpoint         string
	Id                    string
	Secret                string
}

func NewClient(serverBaseUrl, id, secret string) *Client {
	return &Client{
		Log:                   &DefaultLogger{},
		httpClient:            http.DefaultClient,
		ServerBaseUrl:         serverBaseUrl,
		AuthorizationEndpoint: "/authorize",
		TokenEndpoint:         "/token",
		Id:                    id,
		Secret:                secret,
	}
}

func (c *Client) authorize(w http.ResponseWriter, responseType, redirectUri, scope, state string) (err error) {
	var uri *url.URL
	uri, err = url.Parse(c.ServerBaseUrl + c.AuthorizationEndpoint)
	if err != nil {
		return
	}
	uri.Query().Set(ResponseTypeKey, responseType)
	uri.Query().Set(ClientIdKey, c.Id)
	uri.Query().Set(RedirectUriKey, redirectUri)
	uri.Query().Set(ScopeKey, scope)
	uri.Query().Set(StateKey, state)
	var resp *http.Response
	resp, err = c.httpClient.Get(uri.String())
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return
}

func (c *Client) AuthorizeAuthorizationCode(w http.ResponseWriter, redirectUri, scope, state string) (err error) {
	return c.authorize(w, CodeKey, redirectUri, scope, state)
}

func (c *Client) TokenAuthorizationCode(code, redirectUri, state string) (model *TokenResponse, err error) {
	values := url.Values{
		CodeKey:        []string{CodeKey},
		RedirectUriKey: []string{redirectUri},
		StateKey:       []string{state},
	}
	return c.token(CodeKey, values)
}

func (c *Client) AuthorizeImplicit(w http.ResponseWriter, redirectUri, scope, state string) (err error) {
	return c.authorize(w, TokenKey, redirectUri, scope, state)
}

func (c *Client) token(grantType string, values url.Values) (model *TokenResponse, err error) {
	var uri *url.URL
	uri, err = url.Parse(c.ServerBaseUrl + c.TokenEndpoint)
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
	req, err = http.NewRequest(http.MethodPost, uri.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.Id, c.Secret)
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
	if resp.StatusCode != http.StatusOK || strings.Index(string(body), ErrorKey) > -1 {
		errModel := ErrorResponse{}
		err = json.Unmarshal(body, &errModel)
		if err != nil {
			return
		}
		err = Errors[errModel.Error]
	} else {
		model = &TokenResponse{}
		err = json.Unmarshal(body, model)
	}
	return
}

func (c *Client) TokenResourceOwnerPasswordCredentials(username, password string) (model *TokenResponse, err error) {
	values := url.Values{
		UsernameKey: []string{username},
		PasswordKey: []string{password},
	}
	return c.token(PasswordKey, values)
}

func (c *Client) TokenClientCredentials() (model *TokenResponse, err error) {
	return c.token(ClientCredentialsKey, nil)
}

func (c *Client) RefreshToken(refreshToken string) (model *TokenResponse, err error) {
	values := url.Values{
		RefreshTokenKey: []string{refreshToken},
	}
	return c.token(RefreshTokenKey, values)
}
