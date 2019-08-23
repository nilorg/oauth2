package oauth2

import "errors"

var (
	ErrRequestMethod  = errors.New("incorrect request method")
	ErrInvalidRequest = errors.New("invalid_request")
	// ErrUnauthorizedClient 未经授权的客户端
	ErrUnauthorizedClient = errors.New("unauthorized_client")
	// ErrAccessDenied 拒绝访问
	ErrAccessDenied = errors.New("access_denied")
	// ErrUnsupportedResponseType 不支持的响应类型
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	// ErrInvalidScope 无效Scope
	ErrInvalidScope  = errors.New("invalid_scope")
	// ErrTemporarilyUnavailable 暂时不可用
	ErrTemporarilyUnavailable = errors.New("temporarily_unavailable")
	ErrServerError   = errors.New("server_error")
	ErrInvalidClient = errors.New("invalid_client")
)

var (
	ErrCheckClientBasicFuncNil = errors.New("OAuth2 Server CheckClientBasic Is Nil")
)

var (
	// ErrorDescription 错误详情
	ErrorDescription = map[string]string{
		"invalid_request": `The request is missing a required parameter, includes an
               invalid parameter value, includes a parameter more than
               once, or is otherwise malformed.`,
		"invalid_client": `Client authentication failed (e.g., unknown client, no
               client authentication included, or unsupported
               authentication method).  The authorization server MAY
               return an HTTP 401 (Unauthorized) status code to indicate
               which HTTP authentication schemes are supported.  If the
               client attempted to authenticate via the "Authorization"
               request header field, the authorization server MUST
               respond with an HTTP 401 (Unauthorized) status code and
               include the "WWW-Authenticate" response header field
               matching the authentication scheme used by the client.`,
		"invalid_grant": `The provided authorization grant (e.g., authorization
               code, resource owner credentials) or refresh token is
               invalid, expired, revoked, does not match the redirection
               URI used in the authorization request, or was issued to
               another client.`,
		"unauthorized_client": `The authenticated client is not authorized to use this
               authorization grant type.`,
		"unsupported_response_type": `The authorization server does not support obtaining an
               authorization code using this method.`,
		"unsupported_grant_type": `The authorization grant type is not supported by the
               authorization server.`,
		"invalid_scope": `The requested scope is invalid, unknown, malformed, or
               exceeds the scope granted by the resource owner.`,
	}
)
