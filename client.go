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
	httpclient := &http.Client{}
	httpclient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		Log:                   &DefaultLogger{},
		httpClient:            httpclient,
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
	query := uri.Query()
	query.Set(ResponseTypeKey, responseType)
	query.Set(ClientIdKey, c.Id)
	query.Set(RedirectUriKey, redirectUri)
	query.Set(ScopeKey, scope)
	query.Set(StateKey, state)
	uri.RawQuery = query.Encode()
	var resp *http.Response
	resp, err = c.httpClient.Get(uri.String())
	if err != nil {
		return
	}
	w.Header().Set("Location", resp.Header.Get("Location"))
	w.WriteHeader(resp.StatusCode)
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return
}

func (c *Client) AuthorizeAuthorizationCode(w http.ResponseWriter, redirectUri, scope, state string) (err error) {
	return c.authorize(w, CodeKey, redirectUri, scope, state)
}

func (c *Client) TokenAuthorizationCode(code, redirectUri, state string) (token *TokenResponse, err error) {
	values := url.Values{
		CodeKey:        []string{code},
		RedirectUriKey: []string{redirectUri},
		StateKey:       []string{state},
	}
	return c.token(AuthorizationCodeKey, values)
}

func (c *Client) AuthorizeImplicit(w http.ResponseWriter, redirectUri, scope, state string) (err error) {
	return c.authorize(w, TokenKey, redirectUri, scope, state)
}

func (c *Client) token(grantType string, values url.Values) (token *TokenResponse, err error) {
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
		token = &TokenResponse{}
		err = json.Unmarshal(body, token)
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
