package oauth2

import (
	"context"
	"errors"
)
var (
	// ErrContextNotFoundClientBasic 上下文不存在客户端信息
	ErrContextNotFoundClientBasic = errors.New("上下文不存在客户端信息")
)
type clientBasicKey struct{}

// ClientBasicFromContext 从上下文中获取微信客户端
func ClientBasicFromContext(ctx context.Context) (*ClientBasic, error) {
	c, ok := ctx.Value(clientBasicKey{}).(*ClientBasic)
	if !ok {
		return nil, ErrContextNotFoundClientBasic
	}
	return c, nil
}

// NewClientBasicContext 创建客户端上下文
func NewClientBasicContext(ctx context.Context, basic *ClientBasic) context.Context {
	return context.WithValue(ctx, clientBasicKey{}, basic)
}