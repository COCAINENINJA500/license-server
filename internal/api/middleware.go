package api

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// statusRecorder 捕获响应状态码,供访问日志使用.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func newRequestID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}

// withRecover panic 不再击穿进程,统一转 500.
func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "内部错误"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withRequestLogging 访问日志: requestID 方法 路径 状态码 耗时.
func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		rec.Header().Set("X-Request-Id", id)
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %s %d %s", id, r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

// withCORS 仅对 /v1/* 开放跨域(客户端 API 可能被浏览器直调).
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// withBodyLimit 限制请求体大小,防止超大 JSON 打爆内存.
func withBodyLimit(next http.Handler, n int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// 每 IP 限流(token bucket)
// ---------------------------------------------------------------------------

type visitor struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

type ipLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rps      rate.Limit
	burst    int
}

func newIPLimiter(rps float64, burst int) *ipLimiter {
	return &ipLimiter{
		visitors: make(map[string]*visitor),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

// visitorIP 解析客户端 IP: 优先 X-Forwarded-For 第一跳(反代场景),否则 RemoteAddr.
func visitorIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// allow 判定该 IP 是否放行,并做惰性清理(表过大时丢弃 10 分钟未活跃项).
func (l *ipLimiter) allow(r *http.Request) bool {
	ip := visitorIP(r)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.visitors) > 4096 {
		for k, v := range l.visitors {
			if now.Sub(v.lastSeen) > 10*time.Minute {
				delete(l.visitors, k)
			}
		}
	}
	v, ok := l.visitors[ip]
	if !ok {
		v = &visitor{lim: rate.NewLimiter(l.rps, l.burst)}
		l.visitors[ip] = v
	}
	v.lastSeen = now
	return v.lim.Allow()
}

// withRateLimit 对指定路径前缀做每 IP 限流(rps<=0 时关闭).
func withRateLimit(next http.Handler, prefix string, l *ipLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l != nil && strings.HasPrefix(r.URL.Path, prefix) {
			if !l.allow(r) {
				w.Header().Set("Retry-After", "1")
				writeErr(w, &httpError{Code: http.StatusTooManyRequests, Msg: "请求过于频繁,请稍后重试"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
