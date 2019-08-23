package oauth2

import "net/http"

// CheckClientBasicMiddleware 检查客户端基本信息
func CheckClientBasicMiddleware(next http.Handler, check CheckClientBasicFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var clientBasic *ClientBasic
		var err error
		clientBasic, err = RequestClientBasic(r)
		if err != nil {
			WriterError(w, err)
			return
		}
		err = check(clientBasic)
		if err != nil {
			WriterError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CloseCacheMiddleware 关闭缓存中间件
func CloseCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//中间件的逻辑在这里实现,在执行传递进来的handler之前
		next.ServeHTTP(w, r)
		//在handler执行之后的中间件逻辑
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	})
}
