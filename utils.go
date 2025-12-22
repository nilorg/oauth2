package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nilorg/sdk/random"
)

// RequestClientBasic 获取请求中的客户端信息
func RequestClientBasic(r *http.Request) (basic *ClientBasic, err error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		username = r.PostFormValue("client_id")
		password = r.PostFormValue("client_secret")
		if username == "" || password == "" {
			err = ErrInvalidClient
			return
		}
	}
	basic = &ClientBasic{
		ID:     username,
		Secret: password,
	}
	return
}
func writerJSON(w http.ResponseWriter, statusCode int, value interface{}) (err error) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	err = json.NewEncoder(w).Encode(value)
	return
}

// WriterJSON 写入Json
func WriterJSON(w http.ResponseWriter, value interface{}) {
	err := writerJSON(w, http.StatusOK, value)
	if err != nil {
		panic(err)
	}
}

// WriterError 写入Error
func WriterError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	if code, ok := ErrStatusCodes[err]; ok {
		statusCode = code
	}
	if werr := writerJSON(w, statusCode, &ErrorResponse{
		Error: err.Error(),
	}); werr != nil {
		panic(werr)
	}
}

// RedirectSuccess 重定向成功
func RedirectSuccess(w http.ResponseWriter, r *http.Request, redirectURI *url.URL, code string) {
	query := redirectURI.Query()
	query.Set(CodeKey, code)
	query.Set(StateKey, r.FormValue(StateKey))
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

// RedirectError 重定向错误
func RedirectError(w http.ResponseWriter, r *http.Request, redirectURI *url.URL, err error) {
	query := redirectURI.Query()
	query.Set(ErrorKey, err.Error())
	query.Set(StateKey, r.FormValue(StateKey))
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

// RandomState 随机State
func RandomState() string {
	return random.AZaz09(6)
}

// RandomCode 随机Code
func RandomCode() string {
	return random.AZaz09(12)
}

// RandomDeviceCode 随机DeviceCode
func RandomDeviceCode() string {
	return random.AZaz09(32)
}

// RandomUserCode 随机用户code
func RandomUserCode() string {
	return fmt.Sprintf("%s-%s", random.Number(3), random.Number(3))
}

// StringSplit strings.Split
func StringSplit(s, sep string) (results []string) {
	results = strings.Split(s, sep)
	if len(results) == 1 {
		if results[0] == "" {
			results = []string{}
		}
	}
	return
}

// VerifyCodeChallenge 验证 PKCE code_verifier (RFC 7636 Section 4.6)
// Verify PKCE code_verifier against code_challenge
func VerifyCodeChallenge(codeChallenge, codeChallengeMethod, codeVerifier string) bool {
	if codeChallenge == "" {
		// 没有 code_challenge，无需验证
		// No code_challenge, no verification needed
		return true
	}
	if codeVerifier == "" {
		// 有 code_challenge 但没有 code_verifier，验证失败
		// Has code_challenge but no code_verifier, verification fails
		return false
	}

	switch codeChallengeMethod {
	case CodeChallengeMethodS256, "": // S256 是默认方法 / S256 is the default method
		// code_challenge = BASE64URL(SHA256(code_verifier))
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return codeChallenge == computed
	case CodeChallengeMethodPlain:
		// code_challenge = code_verifier
		return codeChallenge == codeVerifier
	default:
		// 不支持的方法
		// Unsupported method
		return false
	}
}

// GenerateCodeChallenge 生成 PKCE code_challenge (RFC 7636)
// Generate PKCE code_challenge from code_verifier
func GenerateCodeChallenge(codeVerifier, method string) string {
	switch method {
	case CodeChallengeMethodS256, "":
		hash := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(hash[:])
	case CodeChallengeMethodPlain:
		return codeVerifier
	default:
		return ""
	}
}

// RandomCodeVerifier 生成随机 PKCE code_verifier (RFC 7636 Section 4.1)
// Generate random PKCE code_verifier (43-128 characters)
func RandomCodeVerifier() string {
	return random.AZaz09(43)
}
