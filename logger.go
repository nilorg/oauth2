package oauth2

import "fmt"

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

type DefaultLogger struct{}

func (*DefaultLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("OAuth2 [DEBUG] "+format+"\n", args...)
}
func (*DefaultLogger) Debugln(args ...interface{}) {
	fmt.Println("OAuth2 [DEBUG] ", args)
}
func (*DefaultLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("OAuth2 [ERROR] "+format+"\n", args...)
}
func (*DefaultLogger) Errorln(args ...interface{}) {
	fmt.Println("OAuth2 [ERROR] ", args)
}
