package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Server struct {
	VerifyClient           VerifyClientFunc
	VerifyCredentialsScope VerifyCredentialsScopeFunc
	VerifyPassword         VerifyPasswordFunc
	VerifyAuthorization    VerifyAuthorizationFunc
	GenerateCode           GenerateCodeFunc
	VerifyCode             VerifyCodeFunc
	serveMux               *http.ServeMux
	HandleAuthorize        http.HandlerFunc
	HandleToken            http.HandlerFunc
	Log                    Logger
	JwtIssuer              string
}

func NewServer() *Server {
	serveMux := http.NewServeMux()
	return &Server{
		Log:       &DefaultLogger{},
		serveMux:  serveMux,
		JwtIssuer: "github.com/nilorg/oauth2",
	}
}

func (srv *Server) Init() {
	if srv.VerifyClient == nil {
		panic(ErrVerifyClientFuncNil)
	}
	if srv.VerifyCredentialsScope == nil {
		panic(ErrVerifyCredentialsScopeFuncNil)
	}
	if srv.VerifyPassword == nil {
		panic(ErrVerifyPasswordFuncNil)
	}
	if srv.VerifyAuthorization == nil {
		panic(ErrVerifyAuthorizationFuncNil)
	}
	if srv.GenerateCode == nil {
		panic(ErrGenerateCodeFuncNil)
	}
	if srv.VerifyCode == nil {
		panic(ErrVerifyCodeFuncNil)
	}
	if srv.HandleAuthorize == nil {
		srv.HandleAuthorize = func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				WriterError(w, ErrRequestMethod)
			} else {
				srv.handleAuthorize(w, r)
			}
		}
	}

	if srv.HandleToken == nil {
		srv.HandleToken = func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				WriterError(w, ErrRequestMethod)
				return
			}
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				WriterError(w, ErrInvalidRequest)
				return
			}
			srv.handleToken(w, r)
		}
	}
	srv.Log.Debugf("GET %s", "/authorize")
	srv.serveMux.Handle("/authorize", srv.HandleAuthorize)
	srv.Log.Debugf("POST %s", "/token")
	srv.serveMux.Handle("/token", srv.HandleToken)
}

func (srv *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// 判断参数
	queryValues := r.URL.Query()
	responseType := queryValues.Get(ResponseTypeKey)
	clientID := queryValues.Get(ClientIdKey)
	redirectURIStr := queryValues.Get(RedirectUriKey)
	redirectURI, err := url.Parse(redirectURIStr)
	if err != nil {
		WriterError(w, ErrInvalidRequest)
		return
	}
	scope := queryValues.Get(ScopeKey)
	state := queryValues.Get(StateKey)
	if responseType == "" || clientID == "" {
		RedirectError(w, r, redirectURI, ErrInvalidRequest)
		return
	}
	switch responseType {
	case CodeKey:
		code, err := srv.authorizeAuthorizationCode(clientID, redirectURIStr, scope)
		if err != nil {
			RedirectError(w, r, redirectURI, err)
		} else {
			RedirectSuccess(w, r, redirectURI, code)
		}
		break
	case TokenKey:
		model, err := srv.authorizeImplicit(clientID, redirectURIStr, scope)
		if err != nil {
			RedirectError(w, r, redirectURI, err)
		} else {
			http.Redirect(w, r, fmt.Sprintf("%s#access_token=%s&state=%s&token_type=%s&expires_in=%d", redirectURIStr, model.AccessToken, state, model.TokenType, model.ExpiresIn), http.StatusFound)
		}
		break
	default:
		RedirectError(w, r, redirectURI, ErrUnsupportedResponseType)
		break
	}
}

func (srv *Server) handleToken(w http.ResponseWriter, r *http.Request) {

	var reqClientBasic *ClientBasic
	var err error
	reqClientBasic, err = RequestClientBasic(r)
	if err != nil {
		WriterError(w, err)
		return
	}
	var clientBasic *ClientBasic
	clientBasic, err = srv.VerifyClient(reqClientBasic.ID)
	if err != nil {
		WriterError(w, err)
		return
	}
	if reqClientBasic.ID != clientBasic.ID || reqClientBasic.Secret != clientBasic.Secret {
		WriterError(w, ErrUnauthorizedClient)
		return
	}

	grantType := r.PostFormValue(GrantTypeKey)
	if grantType == "" {
		WriterError(w, ErrInvalidRequest)
		return
	}
	if grantType == RefreshTokenKey {
		refreshToken := r.PostFormValue(RefreshTokenKey)
		model, err := srv.refreshToken(clientBasic, refreshToken)
		if err != nil {
			WriterError(w, err)
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == AuthorizationCodeKey {
		code := r.PostFormValue(CodeKey)
		redirectURIStr := r.PostFormValue(RedirectUriKey)
		if code == "" || redirectURIStr == "" {
			WriterError(w, ErrInvalidRequest)
			return
		}
		var model *TokenResponse
		model, err := srv.tokenAuthorizationCode(clientBasic, code, redirectURIStr)
		if err != nil {
			WriterError(w, err)
			return
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == PasswordKey {
		username := r.PostFormValue(UsernameKey)
		password := r.PostFormValue(PasswordKey)
		scope := r.PostFormValue(ScopeKey)
		if username == "" || password == "" {
			WriterError(w, ErrInvalidRequest)
			return
		}
		var model *TokenResponse
		model, err := srv.tokenResourceOwnerPasswordCredentials(clientBasic, username, password, scope)
		if err != nil {
			WriterError(w, err)
			return
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == ClientCredentialsKey {
		scope := r.PostFormValue(ScopeKey)
		model, err := srv.tokenClientCredentials(clientBasic, scope)
		if err != nil {
			WriterError(w, err)
			return
		} else {
			WriterJSON(w, model)
		}
	} else {
		WriterError(w, ErrUnsupportedGrantType)
	}
}

func (srv *Server) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	srv.serveMux.ServeHTTP(res, req)
}

// 授权码（authorization-code）
func (srv *Server) authorizeAuthorizationCode(clientID, redirectUri, scope string) (code string, err error) {
	return srv.GenerateCode(clientID, redirectUri, strings.Split(scope, " "))
}

func (srv *Server) tokenAuthorizationCode(client *ClientBasic, code, redirectUri string) (token *TokenResponse, err error) {
	var value *CodeValue
	value, err = srv.VerifyCode(code, client.ID, redirectUri)
	if err != nil {
		return
	}
	tokenClaims := NewJwtClaims()
	tokenClaims.Audience = redirectUri
	var tokenStr string
	tokenStr, err = client.GenerateAccessToken(tokenClaims)
	if err != nil {
		return
	}
	var refreshTokenStr string
	refreshTokenStr, err = client.GenerateRefreshToken(srv.JwtIssuer, tokenStr)
	token = &TokenResponse{
		AccessToken:  tokenStr,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    tokenClaims.ExpiresAt,
		RefreshToken: refreshTokenStr,
		Scope:        strings.Join(value.Scope, " "),
	}
	return
}

// 隐藏式（implicit）
func (srv *Server) authorizeImplicit(clientID, redirectUri, scope string) (token *TokenResponse, err error) {
	var client *ClientBasic
	client, err = srv.VerifyClient(clientID)
	if err != nil {
		return
	}
	err = srv.VerifyAuthorization(clientID, redirectUri, strings.Split(scope, " "))
	if err != nil {
		return
	}
	tokenClaims := NewJwtClaims()
	tokenClaims.Audience = redirectUri
	var tokenStr string
	tokenStr, err = client.GenerateAccessToken(tokenClaims)
	if err != nil {
		return
	}
	var refreshToken string
	refreshToken, err = client.GenerateRefreshToken(srv.JwtIssuer, tokenStr)
	token = &TokenResponse{
		AccessToken:  tokenStr,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    tokenClaims.ExpiresAt,
		RefreshToken: refreshToken,
		Scope:        scope,
	}
	return
}

// 密码式（password）
func (srv *Server) tokenResourceOwnerPasswordCredentials(client *ClientBasic, username, password, scope string) (token *TokenResponse, err error) {
	err = srv.VerifyPassword(username, password, strings.Split(scope, " "))
	if err != nil {
		return
	}
	tokenClaims := NewJwtClaims()
	var tokenStr string
	tokenStr, err = client.GenerateAccessToken(tokenClaims)
	if err != nil {
		return
	}
	var refreshToken string
	refreshToken, err = client.GenerateRefreshToken(srv.JwtIssuer, tokenStr)
	token = &TokenResponse{
		AccessToken:  tokenStr,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    tokenClaims.ExpiresAt,
		RefreshToken: refreshToken,
		Scope:        scope,
	}
	return
}

// 客户端凭证（client credentials）
func (srv *Server) tokenClientCredentials(client *ClientBasic, scope string) (token *TokenResponse, err error) {
	err = srv.VerifyCredentialsScope(client.ID, strings.Split(scope, " "))
	if err != nil {
		return
	}
	claims := NewJwtClaims()
	var tokenStr string
	tokenStr, err = client.GenerateAccessToken(claims)
	if err != nil {
		return
	}
	var refreshToken string
	refreshToken, err = client.GenerateRefreshToken(srv.JwtIssuer, tokenStr)
	if err != nil {
		return
	}
	token = &TokenResponse{
		AccessToken:  tokenStr,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    claims.ExpiresAt,
		RefreshToken: refreshToken,
		Scope:        scope,
	}
	return
}

// 刷新Token
func (srv *Server) refreshToken(client *ClientBasic, refreshToken string) (token *TokenResponse, err error) {
	refreshTokenClaims := NewJwtClaims()
	refreshTokenClaims, err = client.ParseAccessToken(refreshToken)
	if err != nil {
		return
	}
	if refreshTokenClaims.Subject != client.ID {
		err = ErrUnauthorizedClient
		return
	}
	if refreshTokenClaims.Scope != ScopeRefreshToken {
		err = ErrInvalidScope
		return
	}
	refreshTokenClaims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()

	tokenClaims := NewJwtClaims()
	tokenClaims, err = client.ParseAccessToken(refreshTokenClaims.Id)
	if err != nil {
		return
	}
	if tokenClaims.Subject != client.ID {
		err = ErrUnauthorizedClient
		return
	}
	tokenClaims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()

	var refreshTokenStr string
	refreshTokenStr, err = client.GenerateAccessToken(refreshTokenClaims)
	if err != nil {
		return
	}
	var tokenStr string
	tokenStr, err = client.GenerateAccessToken(tokenClaims)
	if err != nil {
		return
	}
	token = &TokenResponse{
		AccessToken:  tokenStr,
		RefreshToken: refreshTokenStr,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    refreshTokenClaims.ExpiresAt,
		Scope:        tokenClaims.Scope,
	}
	return
}
