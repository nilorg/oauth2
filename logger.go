package oauth2

import (
	"context"
	"fmt"
)

// Logger logger
type Logger interface {
	// Debugf 测试
	Debugf(ctx context.Context, format string, args ...interface{})
	// Debugln 测试
	Debugln(ctx context.Context, args ...interface{})
	// Errorf 错误
	Errorf(ctx context.Context, format string, args ...interface{})
	// Errorln 错误
	Errorln(ctx context.Context, args ...interface{})
}

// DefaultLogger ...
type DefaultLogger struct{}

// Debugf ...
func (*DefaultLogger) Debugf(_ context.Context, format string, args ...interface{}) {
	fmt.Printf("OAuth2 [DEBUG] "+format+"\n", args...)
}

// Debugln ...
func (*DefaultLogger) Debugln(_ context.Context, args ...interface{}) {
	fmt.Println("OAuth2 [DEBUG] ", args)
}

// Errorf ...
func (*DefaultLogger) Errorf(_ context.Context, format string, args ...interface{}) {
	fmt.Printf("OAuth2 [ERROR] "+format+"\n", args...)
}

// Errorln ...
func (*DefaultLogger) Errorln(_ context.Context, args ...interface{}) {
	fmt.Println("OAuth2 [ERROR] ", args)
}
