package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
)

type Server struct {
	CheckClientBasic   CheckClientBasicFunc
	serveMux           *http.ServeMux
	HandleAuthorize    http.HandlerFunc
	HandleToken        http.HandlerFunc
	authorizationGrant AuthorizationGranter
	Log                Logger
}

func NewServer(authorizationGrant AuthorizationGranter) *Server {
	serveMux := http.NewServeMux()
	return &Server{
		Log:                &DefaultLogger{},
		authorizationGrant: authorizationGrant,
		serveMux:           serveMux,
	}
}

func (srv *Server) Init() {
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
				fmt.Println("not Post")
				WriterError(w, ErrRequestMethod)
				return
			}
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				fmt.Println("x-www-form-urlencoded")
				WriterError(w, ErrInvalidRequest)
				return
			}
			srv.handleToken(w, r)
		}
	}
	srv.Log.Debugf("GET %s", "/authorize")
	srv.serveMux.Handle("/authorize", srv.HandleAuthorize)
	srv.Log.Debugf("POST %s", "/token")
	srv.serveMux.Handle("/token", CheckClientBasicMiddleware(srv.HandleToken, srv.CheckClientBasic))
}

func (srv *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	basic, _ := RequestClientBasic(r)
	ctx := NewClientBasicContext(r.Context(), basic)
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
		code, err := srv.authorizationGrant.AuthorizeAuthorizationCode(ctx, clientID, redirectURIStr, scope, state)
		if err != nil {
			RedirectError(w, r, redirectURI, ErrInvalidRequest)
		} else {
			RedirectSuccess(w, r, redirectURI, code)
		}
		break
	case TokenKey:
		model, err := srv.authorizationGrant.AuthorizeImplicit(ctx, clientID, redirectURIStr, scope, state)
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
	basic, _ := RequestClientBasic(r)
	ctx := NewClientBasicContext(r.Context(), basic)

	grantType := r.PostFormValue(GrantTypeKey)
	if grantType == "" {
		WriterError(w, ErrInvalidRequest)
		return
	}
	if grantType == RefreshTokenKey {
		refreshToken := r.PostFormValue(RefreshTokenKey)
		model, err := srv.authorizationGrant.RefreshToken(ctx, refreshToken)
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
		var model *TokenResponseModel
		model, err := srv.authorizationGrant.TokenAuthorizationCode(ctx, code, redirectURIStr)
		if err != nil {
			WriterError(w, ErrInvalidRequest)
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
		var model *TokenResponseModel
		model, err := srv.authorizationGrant.TokenResourceOwnerPasswordCredentials(ctx, username, password, scope)
		if err != nil {
			WriterError(w, ErrInvalidRequest)
			return
		} else {
			WriterJSON(w, model)
		}
	} else if grantType == ClientCredentialsKey {
		scope := r.PostFormValue(ScopeKey)
		model, err := srv.authorizationGrant.TokenClientCredentials(ctx, scope)
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
