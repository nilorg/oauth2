package oauth2

import "net/http"

// CheckClientBasicMiddleware 检查客户端基本信息
func CheckClientBasicMiddleware(next http.Handler, check VerifyClientFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqClientBasic *ClientBasic
		var err error
		reqClientBasic, err = RequestClientBasic(r)
		if err != nil {
			WriterError(w, err)
			return
		}
		var clientBasic *ClientBasic
		clientBasic, err = check(reqClientBasic.ID)
		if err != nil {
			WriterError(w, err)
			return
		}
		if reqClientBasic.ID != clientBasic.ID || reqClientBasic.Secret != clientBasic.Secret {
			WriterError(w, ErrUnauthorizedClient)
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
