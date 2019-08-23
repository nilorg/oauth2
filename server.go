package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
)

type DefaultServer struct {
	CheckClientBasic CheckClientBasicFunc
	serveMux         *http.ServeMux
	HandleAuthorize  http.HandlerFunc
	HandleToken      http.HandlerFunc
	Service          Serveer
}

func NewServer(service Serveer) *DefaultServer {
	serveMux := http.NewServeMux()
	return &DefaultServer{
		Service:  service,
		serveMux: serveMux,
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
	if redirectURIStr == "" {
		redirectURIStr = ""
	}
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
		code, err := srv.Service.AuthorizeAuthorizationCode(clientID, redirectURIStr, scope, state)
		if err != nil {
			RedirectError(w, r, redirectURI, ErrInvalidRequest)
		} else {
			redirectURI.Query().Set(CodeKey, code)
			redirectURI.Query().Set(StateKey, state)
			RedirectSuccess(w, r, redirectURI, code)
		}
		break
	case TokenKey:
		model, err := srv.Service.AuthorizeImplicit(clientID, redirectURIStr, scope, state)
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

}

func (srv *DefaultServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	srv.serveMux.ServeHTTP(res, req)
}
