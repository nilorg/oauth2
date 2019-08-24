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
	ErrUnsupportedGrantType    = errors.New("unsupported_grant_type")
	// ErrInvalidScope 无效Scope
	ErrInvalidScope = errors.New("invalid_scope")
	// ErrTemporarilyUnavailable 暂时不可用
	ErrTemporarilyUnavailable = errors.New("temporarily_unavailable")
	ErrServerError            = errors.New("server_error")
	ErrInvalidClient          = errors.New("invalid_client")
)

var (
	ErrCheckClientBasicFuncNil = errors.New("OAuth2 Server CheckClientBasic Is Nil")
	ErrInvalidAccessToken      = errors.New("invalid_access_token")
	ErrStateValueDidNotMatch   = errors.New("state value did not match")
	ErrMissingAccessToken      = errors.New("missing access token")
)
