package oauth2

import (
	"context"
	"errors"
)

// openIDKey OpenID上下文键类型 / Context key type for OpenID
type openIDKey struct{}

var (
	// ErrContextNotFoundOpenID 上下文不存在OpenID / OpenID not found in context
	ErrContextNotFoundOpenID = errors.New("openid not found in context")
)

// OpenIDFromContext 从上下文中获取OpenID / Get OpenID from context
func OpenIDFromContext(ctx context.Context) (string, error) {
	openID, ok := ctx.Value(openIDKey{}).(string)
	if !ok {
		return "", ErrContextNotFoundOpenID
	}
	return openID, nil
}

// NewOpenIDContext 创建包含OpenID的上下文 / Create context with OpenID
func NewOpenIDContext(ctx context.Context, openID string) context.Context {
	return context.WithValue(ctx, openIDKey{}, openID)
}
