package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Server OAuth2Server
type Server struct {
	VerifyClient        VerifyClientFunc
	VerifyScope         VerifyScopeFunc
	VerifyPassword      VerifyPasswordFunc
	VerifyRedirectURI   VerifyRedirectURIFunc
	GenerateCode        GenerateCodeFunc
	VerifyCode          VerifyCodeFunc
	GenerateAccessToken GenerateAccessTokenFunc
	RefreshAccessToken  RefreshAccessTokenFunc
	ParseAccessToken    ParseAccessTokenFunc
	Log                 Logger
	JwtIssuer           string
}

// NewServer 创建服务器
func NewServer() *Server {
	return &Server{
		Log:       &DefaultLogger{},
		JwtIssuer: DefaultJwtIssuer,
	}
}

// Init 初始化
func (srv *Server) Init() {
	if srv.VerifyClient == nil {
		panic(ErrVerifyClientFuncNil)
	}
	if srv.VerifyPassword == nil {
		panic(ErrVerifyPasswordFuncNil)
	}
	if srv.VerifyRedirectURI == nil {
		panic(ErrVerifyRedirectURIFuncNil)
	}
	if srv.GenerateCode == nil {
		panic(ErrGenerateCodeFuncNil)
	}
	if srv.VerifyCode == nil {
		panic(ErrVerifyCodeFuncNil)
	}
	if srv.VerifyScope == nil {
		panic(ErrVerifyScopeFuncNil)
	}
	if srv.GenerateAccessToken == nil {
		panic(ErrGenerateAccessTokenFuncNil)
	}
	if srv.RefreshAccessToken == nil {
		panic(ErrRefreshAccessTokenFuncNil)
	}
	if srv.ParseAccessToken == nil {
		panic(ErrParseAccessTokenFuncNil)
	}
}

// HandleAuthorize 处理Authorize
func (srv *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// 判断参数
	responseType := r.FormValue(ResponseTypeKey)
	clientID := r.FormValue(ClientIDKey)
	scope := r.FormValue(ScopeKey)
	state := r.FormValue(StateKey)
	redirectURIStr := r.FormValue(RedirectURIKey)
	redirectURI, err := url.Parse(redirectURIStr)
	if err != nil {
		WriterError(w, ErrInvalidRequest)
		return
	}
	if responseType == "" || clientID == "" {
		RedirectError(w, r, redirectURI, ErrInvalidRequest)
		return
	}

	err = srv.VerifyRedirectURI(clientID, redirectURI.String())
	if err != nil {
		RedirectError(w, r, redirectURI, err)
		return
	}

	if err = srv.VerifyScope(StringSplit(scope, " ")); err != nil {
		// ErrInvalidScope
		RedirectError(w, r, redirectURI, err)
		return
	}
	var openID string
	openID, err = OpenIDFromContext(r.Context())
	if err != nil {
		RedirectError(w, r, redirectURI, ErrServerError)
		return
	}
	switch responseType {
	case CodeKey:
		var code string
		code, err = srv.authorizeAuthorizationCode(clientID, redirectURIStr, scope, openID)
		if err != nil {
			RedirectError(w, r, redirectURI, err)
		} else {
			RedirectSuccess(w, r, redirectURI, code)
		}
		break
	case TokenKey:
		var token *TokenResponse
		token, err = srv.authorizeImplicit(clientID, scope, openID)
		if err != nil {
			RedirectError(w, r, redirectURI, err)
		} else {
			http.Redirect(w, r, fmt.Sprintf("%s#access_token=%s&state=%s&token_type=%s&expires_in=%d", redirectURIStr, token.AccessToken, state, token.TokenType, token.ExpiresIn), http.StatusFound)
		}
		break
	default:
		RedirectError(w, r, redirectURI, ErrUnsupportedResponseType)
		break
	}
}

// HandleToken 处理Token
func (srv *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	var reqClientBasic *ClientBasic
	var err error
	reqClientBasic, err = RequestClientBasic(r)
	if err != nil {
		WriterError(w, err)
		return
	}

	err = srv.VerifyClient(reqClientBasic)
	if err != nil {
		WriterError(w, err)
		return
	}

	grantType := r.PostFormValue(GrantTypeKey)
	if grantType == "" {
		WriterError(w, ErrInvalidRequest)
		return
	}

	scope := r.PostFormValue(ScopeKey)
	if err = srv.VerifyScope(StringSplit(scope, " ")); err != nil {
		// ErrInvalidScope
		WriterError(w, err)
		return
	}

	if grantType == RefreshTokenKey {
		refreshToken := r.PostFormValue(RefreshTokenKey)
		model, err := srv.RefreshAccessToken(reqClientBasic.ID, refreshToken)
		if err != nil {
			WriterError(w, err)
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == AuthorizationCodeKey {
		code := r.PostFormValue(CodeKey)
		redirectURIStr := r.PostFormValue(RedirectURIKey)
		if code == "" || redirectURIStr == "" {
			WriterError(w, ErrInvalidRequest)
			return
		}
		var model *TokenResponse
		model, err = srv.tokenAuthorizationCode(reqClientBasic, code, redirectURIStr)
		if err != nil {
			WriterError(w, err)
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == PasswordKey {
		username := r.PostFormValue(UsernameKey)
		password := r.PostFormValue(PasswordKey)
		if username == "" || password == "" {
			WriterError(w, ErrInvalidRequest)
			return
		}
		var model *TokenResponse
		model, err := srv.tokenResourceOwnerPasswordCredentials(reqClientBasic, username, password, scope)
		if err != nil {
			WriterError(w, err)
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == ClientCredentialsKey {
		model, err := srv.tokenClientCredentials(reqClientBasic, scope)
		if err != nil {
			WriterError(w, err)
		} else {
			WriterJSON(w, model)
		}
	} else {
		WriterError(w, ErrUnsupportedGrantType)
	}
}

// 授权码（authorization-code）
func (srv *Server) authorizeAuthorizationCode(clientID, redirectURI, scope, openID string) (code string, err error) {
	return srv.GenerateCode(clientID, openID, redirectURI, StringSplit(scope, " "))
}

func (srv *Server) tokenAuthorizationCode(client *ClientBasic, code, redirectURI string) (token *TokenResponse, err error) {
	var value *CodeValue
	value, err = srv.VerifyCode(code, client.ID, redirectURI)
	if err != nil {
		return
	}
	scope := strings.Join(value.Scope, " ")
	token, err = srv.GenerateAccessToken(srv.JwtIssuer, redirectURI, scope, value.OpenID)
	return
}

// 隐藏式（implicit）
func (srv *Server) authorizeImplicit(clientID, scope, openID string) (token *TokenResponse, err error) {
	token, err = srv.GenerateAccessToken(srv.JwtIssuer, clientID, scope, openID)
	return
}

// 密码式（password）
func (srv *Server) tokenResourceOwnerPasswordCredentials(client *ClientBasic, username, password, scope string) (token *TokenResponse, err error) {
	var openID string
	openID, err = srv.VerifyPassword(username, password)
	if err != nil {
		return
	}
	token, err = srv.GenerateAccessToken(srv.JwtIssuer, client.ID, scope, openID)
	return
}

// 客户端凭证（client credentials）
func (srv *Server) tokenClientCredentials(client *ClientBasic, scope string) (token *TokenResponse, err error) {
	token, err = srv.GenerateAccessToken(srv.JwtIssuer, client.ID, scope, "")
	return
}

//
//// 刷新Token
//func (srv *Server) refreshToken(client *ClientBasic, refreshToken string) (token *TokenResponse, err error) {
//	refreshTokenClaims := &JwtClaims{}
//	refreshTokenClaims, err = srv.ParseAccessToken(refreshToken)
//	if err != nil {
//		return
//	}
//	if refreshTokenClaims.Subject != client.ID {
//		err = ErrUnauthorizedClient
//		return
//	}
//	if refreshTokenClaims.Scope != ScopeRefreshToken {
//		err = ErrInvalidScope
//		return
//	}
//	refreshTokenClaims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()
//
//	var tokenClaims *JwtClaims
//	tokenClaims, err = srv.ParseAccessToken(refreshTokenClaims.Id)
//	if err != nil {
//		return
//	}
//	if tokenClaims.Subject != client.ID {
//		err = ErrUnauthorizedClient
//		return
//	}
//	tokenClaims.ExpiresAt = time.Now().Add(AccessTokenExpire).Unix()
//
//	var refreshTokenStr string
//	refreshTokenStr, err = NewAccessToken(refreshTokenClaims, client.TokenVerifyKey())
//	if err != nil {
//		return
//	}
//	var tokenStr string
//	tokenStr, err = NewAccessToken(tokenClaims, client.TokenVerifyKey())
//	token = &TokenResponse{
//		AccessToken:  tokenStr,
//		RefreshToken: refreshTokenStr,
//		TokenType:    TokenTypeBearer,
//		ExpiresIn:    refreshTokenClaims.ExpiresAt,
//		Scope:        tokenClaims.Scope,
//	}
//	return
//}
