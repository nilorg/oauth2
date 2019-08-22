package oauth2

// Logger logger
type Logger interface {
	// Debugf 测试
	Debugf(format string, args ...interface{})
	// Debugln 测试
	Debugln(args ...interface{})
	// Errorf 错误
	Errorf(format string, args ...interface{})
	// Errorln 错误
	Errorln(args ...interface{})
}
