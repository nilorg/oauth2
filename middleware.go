package oauth2

import "net/http"

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
