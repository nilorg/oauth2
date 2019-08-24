package oauth2

import (
	"encoding/json"
	"github.com/nilorg/sdk/random"
	"net/http"
	"net/url"
)

const (
	contentTypeJson = "application/json;charset=UTF-8"
)

// RequestClientBasic 获取请求中的客户端信息
func RequestClientBasic(r *http.Request) (basic *ClientBasic, err error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		err = ErrInvalidClient
		return
	}
	basic = &ClientBasic{
		ID:     username,
		Secret: password,
	}
	return
}
func writerJSON(w http.ResponseWriter, statusCode int, value interface{}) (err error) {
	w.Header().Set("Content-Type", contentTypeJson)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	jsonEncoder := json.NewEncoder(w)
	err = jsonEncoder.Encode(value)
	return
}

// WriterJSON 写入Json
func WriterJSON(w http.ResponseWriter, value interface{}) {
	err := writerJSON(w, http.StatusOK, value)
	if err != nil {
		panic(err)
	}
	return
}

// WriterError 写入Error
func WriterError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	if err == ErrRequestMethod {
		statusCode = http.StatusNotFound
	}
	if werr := writerJSON(w, statusCode, &ErrorResponseModel{
		error: err.Error(),
	}); werr != nil {
		panic(werr)
	}
}

// RedirectSuccess 重定向成功
func RedirectSuccess(w http.ResponseWriter, r *http.Request, redirectURI *url.URL, code string) {
	redirectURI.Query().Set(CodeKey, code)
	redirectURI.Query().Set(StateKey, r.URL.Query().Get(StateKey))
	http.Redirect(w, r, redirectURI.Path, http.StatusFound)
}

// RedirectError 重定向错误
func RedirectError(w http.ResponseWriter, r *http.Request, redirectURI *url.URL, err error) {
	redirectURI.Query().Set(ErrorKey, err.Error())
	redirectURI.Query().Set(StateKey, r.URL.Query().Get(StateKey))
	http.Redirect(w, r, redirectURI.Path, http.StatusFound)
}

func RandomState() string {
	return random.AZaz09(6)
}

func RandomCode() string {
	return random.AZaz09(12)
}
