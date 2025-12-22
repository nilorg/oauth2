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
	// ErrExpiredToken 过期的令牌
	ErrExpiredToken = errors.New("expired_token")
	// ErrAuthorizationPending 授权待定
	// https://tools.ietf.org/html/rfc8628#section-3.5
	ErrAuthorizationPending = errors.New("authorization_pending")
	// ErrSlowDown 轮询太频繁
	// https://tools.ietf.org/html/rfc8628#section-3.5
	ErrSlowDown = errors.New("slow_down")
	// ErrUnsupportedTokenType 不支持的令牌类型
	// https://tools.ietf.org/html/rfc7009#section-4.1.1
	ErrUnsupportedTokenType = errors.New("unsupported_token_type")
)

var (
	// ErrVerifyClientFuncNil VerifyClient函数未设置 / VerifyClient function is not set
	ErrVerifyClientFuncNil = errors.New("OAuth2 Server VerifyClient Is Nil")
	// ErrVerifyClientIDFuncNil VerifyClientID函数未设置 / VerifyClientID function is not set
	ErrVerifyClientIDFuncNil = errors.New("OAuth2 Server VerifyClientID Is Nil")
	// ErrVerifyPasswordFuncNil VerifyPassword函数未设置 / VerifyPassword function is not set
	ErrVerifyPasswordFuncNil = errors.New("OAuth2 Server VerifyPassword Is Nil")
	// ErrVerifyRedirectURIFuncNil VerifyRedirectURI函数未设置 / VerifyRedirectURI function is not set
	ErrVerifyRedirectURIFuncNil = errors.New("OAuth2 Server VerifyRedirectURI Is Nil")
	// ErrGenerateCodeFuncNil GenerateCode函数未设置 / GenerateCode function is not set
	ErrGenerateCodeFuncNil = errors.New("OAuth2 Server GenerateCode Is Nil")
	// ErrVerifyCodeFuncNil VerifyCode函数未设置 / VerifyCode function is not set
	ErrVerifyCodeFuncNil = errors.New("OAuth2 Server VerifyCode Is Nil")
	// ErrVerifyScopeFuncNil VerifyScope函数未设置 / VerifyScope function is not set
	ErrVerifyScopeFuncNil = errors.New("OAuth2 Server VerifyScope Is Nil")
	// ErrGenerateAccessTokenFuncNil GenerateAccessToken函数未设置 / GenerateAccessToken function is not set
	ErrGenerateAccessTokenFuncNil = errors.New("OAuth2 Server GenerateAccessTokenFunc Is Nil")
	// ErrGenerateDeviceAuthorizationFuncNil GenerateDeviceAuthorization函数未设置 / GenerateDeviceAuthorization function is not set
	ErrGenerateDeviceAuthorizationFuncNil = errors.New("OAuth2 Server GenerateDeviceAuthorizationFunc Is Nil")
	// ErrVerifyDeviceCodeFuncNil VerifyDeviceCode函数未设置 / VerifyDeviceCode function is not set
	ErrVerifyDeviceCodeFuncNil = errors.New("OAuth2 Server ErrVerifyDeviceCodeFunc Is Nil")
	// ErrRefreshAccessTokenFuncNil RefreshAccessToken函数未设置 / RefreshAccessToken function is not set
	ErrRefreshAccessTokenFuncNil = errors.New("OAuth2 Server ErrRefreshAccessTokenFuncNil Is Nil")
	// ErrParseAccessTokenFuncNil ParseAccessToken函数未设置 / ParseAccessToken function is not set
	ErrParseAccessTokenFuncNil = errors.New("OAuth2 Server ParseAccessTokenFunc Is Nil")
	// ErrVerifyIntrospectionTokenFuncNil VerifyIntrospectionToken函数未设置 / VerifyIntrospectionToken function is not set
	ErrVerifyIntrospectionTokenFuncNil = errors.New("OAuth2 Server VerifyIntrospectionToken Is Nil")
	// ErrTokenRevocationFuncNil TokenRevocation函数未设置 / TokenRevocation function is not set
	ErrTokenRevocationFuncNil = errors.New("OAuth2 Server TokenRevocation Is Nil")
	// ErrVerifyGrantTypeFuncNil VerifyGrantType函数未设置 / VerifyGrantType function is not set
	ErrVerifyGrantTypeFuncNil = errors.New("OAuth2 Server VerifyGrantType Is Nil")
	// ErrInvalidAccessToken 无效的访问令牌
	ErrInvalidAccessToken = errors.New("invalid_access_token")
	// ErrInvalidRedirectURI 无效的RedirectURI
	ErrInvalidRedirectURI = errors.New("invalid_redirect_uri")
	// ErrStateValueDidNotMatch state值不匹配 / State value did not match
	ErrStateValueDidNotMatch = errors.New("state value did not match")
	// ErrMissingAccessToken 缺少访问令牌 / Missing access token in request
	ErrMissingAccessToken = errors.New("missing access token")
	// ErrAccessToken AccessToken接口未设置 / AccessToken interface is not set
	ErrAccessToken = errors.New("OAuth2 Server AccessToken Is Nil")
)

var (
	// Errors 错误映射表，用于从错误字符串查找错误对象 / Error map for looking up error objects from error strings
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
		ErrExpiredToken.Error():            ErrExpiredToken,
		ErrAuthorizationPending.Error():    ErrAuthorizationPending,
		ErrSlowDown.Error():                ErrSlowDown,
		ErrUnsupportedTokenType.Error():    ErrUnsupportedTokenType,
	}
	// ErrStatusCodes 错误对应的HTTP状态码映射表 / HTTP status codes mapping for errors
	// 根据 RFC 6749 Section 5.2，Token 端点错误应返回 400 Bad Request
	// 仅 invalid_client 在客户端认证失败时返回 401
	// According to RFC 6749 Section 5.2, token endpoint errors should return 400 Bad Request
	// Only invalid_client returns 401 when client authentication fails
	ErrStatusCodes = map[error]int{
		ErrInvalidRequest:          http.StatusBadRequest,          // 400 - RFC 6749 Section 5.2
		ErrUnauthorizedClient:      http.StatusBadRequest,          // 400 - RFC 6749 Section 5.2
		ErrAccessDenied:            http.StatusForbidden,           // 403 - RFC 6749 Section 4.1.2.1
		ErrUnsupportedResponseType: http.StatusBadRequest,          // 400 - RFC 6749 Section 4.1.2.1
		ErrInvalidScope:            http.StatusBadRequest,          // 400 - RFC 6749 Section 5.2
		ErrServerError:             http.StatusInternalServerError, // 500 - RFC 6749 Section 4.1.2.1
		ErrTemporarilyUnavailable:  http.StatusServiceUnavailable,  // 503 - RFC 6749 Section 4.1.2.1
		ErrInvalidClient:           http.StatusUnauthorized,        // 401 - RFC 6749 Section 5.2
		ErrInvalidGrant:            http.StatusBadRequest,          // 400 - RFC 6749 Section 5.2
		ErrUnsupportedGrantType:    http.StatusBadRequest,          // 400 - RFC 6749 Section 5.2
		ErrExpiredToken:            http.StatusUnauthorized,        // 401 - RFC 8628 Section 3.5
		ErrAuthorizationPending:    http.StatusBadRequest,          // 400 - RFC 8628 Section 3.5
		ErrSlowDown:                http.StatusBadRequest,          // 400 - RFC 8628 Section 3.5
		ErrUnsupportedTokenType:    http.StatusServiceUnavailable,  // 503 - RFC 7009 Section 2.2.1
	}
)
