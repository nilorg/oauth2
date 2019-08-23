package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type DefaultServer struct {
	AccessTokenExpire  time.Duration
	CheckClientBasic   CheckClientBasicFunc
	serveMux           *http.ServeMux
	HandleAuthorize    http.HandlerFunc
	HandleToken        http.HandlerFunc
	authorizationGrant AuthorizationGranter
}

func NewServer(authorizationGrant AuthorizationGranter) *DefaultServer {
	serveMux := http.NewServeMux()
	return &DefaultServer{
		AccessTokenExpire:  time.Second * 3600,
		authorizationGrant: authorizationGrant,
		serveMux:           serveMux,
	}
}

func (srv *DefaultServer) Init() {
	if srv.CheckClientBasic == nil {
		panic(ErrCheckClientBasicFuncNil)
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
			} else if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				WriterError(w, ErrInvalidRequest)
			} else {
				srv.handleToken(w, r)
			}
		}
	}
	srv.serveMux.Handle("/authorize", srv.HandleAuthorize)
	srv.serveMux.Handle("/token", CheckClientBasicMiddleware(srv.HandleToken, srv.CheckClientBasic))
}

func (srv *DefaultServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
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
		code, err := srv.authorizationGrant.AuthorizeAuthorizationCode(clientID, redirectURIStr, scope, state)
		if err != nil {
			RedirectError(w, r, redirectURI, ErrInvalidRequest)
		} else {
			RedirectSuccess(w, r, redirectURI, code)
		}
		break
	case TokenKey:
		model, err := srv.authorizationGrant.AuthorizeImplicit(clientID, redirectURIStr, scope, state)
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

func (srv *DefaultServer) handleToken(w http.ResponseWriter, r *http.Request) {
	// 判断参数
	queryValues := r.URL.Query()
	grantType := queryValues.Get(GrantTypeKey)
	if grantType == "" {
		WriterError(w, ErrInvalidRequest)
		return
	}
	if grantType == RefreshTokenKey {
		refreshToken := queryValues.Get(RefreshTokenKey)
		model, err := srv.authorizationGrant.RefreshToken(refreshToken)
		if err != nil {
			WriterError(w, err)
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == AuthorizationCodeKey {
		code := queryValues.Get(CodeKey)
		redirectURIStr := queryValues.Get(RedirectUriKey)
		if code == "" || redirectURIStr == "" {
			WriterError(w, ErrInvalidRequest)
			return
		}
		var model *TokenResponseModel
		model, err := srv.authorizationGrant.TokenAuthorizationCode(code, redirectURIStr)
		if err != nil {
			WriterError(w, ErrInvalidRequest)
			return
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == PasswordKey {
		username := queryValues.Get(UsernameKey)
		password := queryValues.Get(PasswordKey)
		if username == "" || password == "" {
			WriterError(w, ErrInvalidRequest)
			return
		}
		var model *TokenResponseModel
		model, err := srv.authorizationGrant.TokenResourceOwnerPasswordCredentials(username, password)
		if err != nil {
			WriterError(w, ErrInvalidRequest)
			return
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == ClientCredentialsKey {
		basic, _ := RequestClientBasic(r)
		ctx := NewClientBasicContext(r.Context(), basic)
		model, err := srv.authorizationGrant.TokenClientCredentials(ctx)
		if err != nil {
			WriterError(w, ErrInvalidRequest)
			return
		} else {
			WriterJSON(w, model)
		}
	}
}

func (srv *DefaultServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	srv.serveMux.ServeHTTP(res, req)
}
