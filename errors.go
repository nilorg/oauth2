package oauth2

import (
	"errors"
	"net/http"
)

var (
	// ErrInvalidRequest 无效的请求
	ErrInvalidRequest = errors.New("invalid_request")
	// ErrUnauthorizedClient 未经授权的客户端
	ErrUnauthorizedClient = errors.New("unauthorized_client")
	// ErrAccessDenied 拒绝访问
	ErrAccessDenied = errors.New("access_denied")
	// ErrUnsupportedResponseType 不支持的response类型
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	// ErrUnsupportedGrantType 不支持的grant类型
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")
	// ErrInvalidGrant 无效的grant
	ErrInvalidGrant = errors.New("invalid_grant")
	// ErrInvalidScope 无效scope
	ErrInvalidScope = errors.New("invalid_scope")
	// ErrTemporarilyUnavailable 暂时不可用
	ErrTemporarilyUnavailable = errors.New("temporarily_unavailable")
	// ErrServerError 服务器错误
	ErrServerError = errors.New("server_error")
	// ErrInvalidClient 无效的客户
	ErrInvalidClient = errors.New("invalid_client")
)

var (
	ErrVerifyClientFuncNil        = errors.New("OAuth2 Server VerifyClient Is Nil")
	ErrVerifyCredentialsFuncNil   = errors.New("OAuth2 Server VerifyCredentials Is Nil")
	ErrVerifyPasswordFuncNil      = errors.New("OAuth2 Server VerifyPassword Is Nil")
	ErrVerifyAuthorizationFuncNil = errors.New("OAuth2 Server VerifyAuthorization Is Nil")
	ErrGenerateCodeFuncNil        = errors.New("OAuth2 Server GenerateCode Is Nil")
	ErrVerifyCodeFuncNil          = errors.New("OAuth2 Server VerifyCode Is Nil")

	// ErrInvalidAccessToken 无效的访问令牌
	ErrInvalidAccessToken    = errors.New("invalid_access_token")
	ErrStateValueDidNotMatch = errors.New("state value did not match")
	ErrMissingAccessToken    = errors.New("missing access token")
)

var (
	Errors = map[string]error{
		ErrVerifyClientFuncNil.Error():   ErrVerifyClientFuncNil,
		ErrInvalidAccessToken.Error():    ErrInvalidAccessToken,
		ErrStateValueDidNotMatch.Error(): ErrStateValueDidNotMatch,
		ErrMissingAccessToken.Error():    ErrMissingAccessToken,

		ErrInvalidRequest.Error():          ErrInvalidRequest,
		ErrUnauthorizedClient.Error():      ErrUnauthorizedClient,
		ErrAccessDenied.Error():            ErrAccessDenied,
		ErrUnsupportedResponseType.Error(): ErrUnsupportedResponseType,
		ErrUnsupportedGrantType.Error():    ErrUnsupportedGrantType,
		ErrInvalidGrant.Error():            ErrInvalidGrant,
		ErrInvalidScope.Error():            ErrInvalidScope,
		ErrTemporarilyUnavailable.Error():  ErrTemporarilyUnavailable,
		ErrServerError.Error():             ErrServerError,
		ErrInvalidClient.Error():           ErrInvalidClient,
	}

	ErrStatusCodes = map[error]int{
		ErrInvalidRequest:          http.StatusBadRequest,
		ErrUnauthorizedClient:      http.StatusUnauthorized,
		ErrAccessDenied:            http.StatusForbidden,
		ErrUnsupportedResponseType: http.StatusUnauthorized,
		ErrInvalidScope:            http.StatusBadRequest,
		ErrServerError:             http.StatusInternalServerError,
		ErrTemporarilyUnavailable:  http.StatusServiceUnavailable,
		ErrInvalidClient:           http.StatusUnauthorized,
		ErrInvalidGrant:            http.StatusUnauthorized,
		ErrUnsupportedGrantType:    http.StatusUnauthorized,
	}
)
