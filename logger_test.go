package oauth2

import (
	"context"
	"testing"
)

func TestDefaultLogger_Debugf(t *testing.T) {
	logger := &DefaultLogger{}
	// 测试不会panic
	logger.Debugf(context.Background(), "test message: %s", "value")
}

func TestDefaultLogger_Debugln(t *testing.T) {
	logger := &DefaultLogger{}
	// 测试不会panic
	logger.Debugln(context.Background(), "test", "message")
}

func TestDefaultLogger_Errorf(t *testing.T) {
	logger := &DefaultLogger{}
	// 测试不会panic
	logger.Errorf(context.Background(), "error message: %s", "value")
}

func TestDefaultLogger_Errorln(t *testing.T) {
	logger := &DefaultLogger{}
	// 测试不会panic
	logger.Errorln(context.Background(), "error", "message")
}

func TestLoggerInterface(t *testing.T) {
	// 验证 DefaultLogger 实现了 Logger 接口
	var _ Logger = &DefaultLogger{}
}
