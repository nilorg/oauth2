package oauth2

import (
	"encoding/json"
	"net/http"
)

// AuthorizationCode
// 授权码模式（authorization code）是功能最完整、流程最严密的授权模式。
// 它的特点就是通过客户端的后台服务器，与"服务提供商"的认证服务器进行互动。
// Implicit
// 简化模式（implicit grant type）不通过第三方应用程序的服务器，直接在浏览器中向认证服务器申请令牌，跳过了"授权码"这个步骤，因此得名。
// 所有步骤在浏览器中完成，令牌对访问者是可见的，且客户端不需要认证。
// ResourceOwnerPasswordCredentials
// 密码模式（Resource Owner Password Credentials Grant）中，用户向客户端提供自己的用户名和密码。客户端使用这些信息，向"服务商提供商"索要授权。
// 在这种模式中，用户必须把自己的密码给客户端，但是客户端不得储存密码。
// 这通常用在用户对客户端高度信任的情况下，比如客户端是操作系统的一部分，或者由一个著名公司出品。
// 而认证服务器只有在其他授权模式无法执行的情况下，才能考虑使用这种模式。
// Clientredentials
// 客户端模式（Client Credentials Grant）指客户端以自己的名义，而不是以用户的名义，向"服务提供商"进行认证。
// 严格地说，客户端模式并不属于OAuth框架所要解决的问题。
// 在这种模式中，用户直接向客户端注册，客户端以自己的名义要求"服务提供商"提供服务，其实不存在授权问题。

type AuthorizeAuthorizationCodeFunc func(clientID, redirectUri, scope, state string) (string, error)
type TokenAuthorizationCodeFunc func(code, redirectUri string) (*TokenResponseModel, error)

//     Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
//               &state=xyz&token_type=example&expires_in=3600
type AuthorizeImplicitFunc func(clientID, redirectUri, scope, state string) error

type TokenResourceOwnerPasswordCredentialsFunc func(username, password string) (*TokenResponseModel, error)

type TokenClientredentialsFunc func(scope string) (*TokenResponseModel, error)

type RefreshTokenFunc func(refreshToken string) (*TokenResponseModel, error)

// CloseCache 关闭缓存
func CloseCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writerJSON(w http.ResponseWriter, statusCode int, value interface{}) (err error) {
	CloseCache(w)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(statusCode)
	jsonEncoder := json.NewEncoder(w)
	err = jsonEncoder.Encode(value)
	return
}

// WriterJSON 写入Json
func WriterJSON(w http.ResponseWriter, value interface{}) (err error) {
	err = writerJSON(w, http.StatusOK, value)
	return
}

// WriterError 写入Error
func WriterError(w http.ResponseWriter, err error) {
	if werr := writerJSON(w, http.StatusBadRequest, map[string]string{
		"error": err.Error(),
	}); werr != nil {
		panic(werr)
	}
}
