package oauth2

import (
	"net/http"
	"net/url"
)

type DefaultServer struct {
	serveMux        *http.ServeMux
	HandleAuthorize http.HandlerFunc
	HandleToken     http.HandlerFunc
	Service         Serveer
}

func NewServer(service Serveer) *DefaultServer {
	serveMux := http.NewServeMux()
	return &DefaultServer{
		Service:  service,
		serveMux: serveMux,
	}
}

func (srv *DefaultServer) Init() {
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
			} else {
				srv.handleToken(w, r)
			}
		}
	}
	srv.serveMux.HandleFunc("/authorize", srv.HandleAuthorize)
	srv.serveMux.HandleFunc("/token", srv.HandleToken)
}

func (srv *DefaultServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// 判断参数
	queryValues := r.URL.Query()
	responseType := queryValues.Get(ResponseTypeKey)
	clientID := queryValues.Get(ClientIdKey)
	if responseType == "" || clientID == "" {
		WriterError(w, ErrInvalidRequest)
		return
	}

	redirectURIStr := queryValues.Get(RedirectUriKey)
	scope := queryValues.Get(ScopeKey)
	state := queryValues.Get(StateKey)

	redirectURI, err := url.Parse(redirectURIStr)
	if err != nil {
		WriterError(w, ErrInvalidRequest)
		return
	}
	switch responseType {
	case CodeKey:
		code, err := srv.Service.AuthorizeAuthorizationCode(clientID, redirectURIStr, scope, state)
		if err != nil {
			WriterError(w, err)
		} else {
			redirectURI.Query().Set(CodeKey, code)
			redirectURI.Query().Set(StateKey, state)
			http.Redirect(w, r, redirectURI.Path, http.StatusFound)
		}
		break
	case TokenKey:
		srv.Service.AuthorizeImplicit(clientID, redirectURIStr, scope, state)
		break
	default:
		WriterError(w, ErrUnsupportedResponseType)
		break
	}
}

func (srv *DefaultServer) handleToken(w http.ResponseWriter, r *http.Request) {

}

func (srv *DefaultServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	srv.serveMux.ServeHTTP(res, req)
}
