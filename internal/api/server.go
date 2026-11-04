// Package api 实现 license-server 的全部 HTTP 行为:客户端 API、管理 API、内嵌管理台.
package api

import (
	"net/http"
	"time"

	"github.com/COCAINENINJA500/license-server/internal/adminui"
	"github.com/COCAINENINJA500/license-server/internal/licensing"
	"github.com/COCAINENINJA500/license-server/internal/store"
)

// maxBodyBytes JSON 请求体上限.
const maxBodyBytes int64 = 1 << 20 // 1 MiB

// Server 聚合依赖并注册全部路由.
type Server struct {
	Store    *store.Store
	Signer   *licensing.Signer
	AdminKey string
	Nonces   *licensing.NonceStore
	Version  string
	Now      func() time.Time // 可注入固定时钟(测试)

	limiter *ipLimiter
}

// NewServer 构造. rps<=0 关闭限流.
func NewServer(st *store.Store, signer *licensing.Signer, adminKey string, nonces *licensing.NonceStore, version string, rateRPS float64, rateBurst int) *Server {
	s := &Server{
		Store:    st,
		Signer:   signer,
		AdminKey: adminKey,
		Nonces:   nonces,
		Version:  version,
		Now:      time.Now,
	}
	if rateRPS > 0 {
		s.limiter = newIPLimiter(rateRPS, rateBurst)
	}
	return s
}

func (s *Server) nowTime() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Routes 组装中间件链与全部路由.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// 健康检查(供负载均衡/容器探活).
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// 客户端 API.
	mux.HandleFunc("GET /v1/pubkey", s.handlePubkey)
	mux.HandleFunc("POST /v1/activate", s.handleActivate)
	mux.HandleFunc("POST /v1/refresh", s.handleRefresh)
	mux.HandleFunc("GET /v1/status", s.handleStatus)

	// 内嵌单租户管理台(页面本身无鉴权,调 API 用 Admin Key).
	mux.HandleFunc("GET /admin", adminui.HTMLHandler())
	mux.HandleFunc("GET /admin/", adminui.HTMLHandler())
	// 实时生成的对接文档与 AI 提示词(可下载/复制给其他 Coding Agent).
	mux.HandleFunc("GET /admin/integration.md", s.requireAdmin(s.handleIntegrationDoc))
	mux.HandleFunc("GET /admin/integration-prompt.txt", s.requireAdmin(s.handleIntegrationPrompt))

	mux.HandleFunc("POST /admin/licenses", s.requireAdmin(s.handleIssue))
	mux.HandleFunc("GET /admin/licenses", s.requireAdmin(s.handleList))
	mux.HandleFunc("GET /admin/stats", s.requireAdmin(s.handleStats))
	mux.HandleFunc("GET /admin/licenses/{id}", s.requireAdmin(s.handleGetOne))
	mux.HandleFunc("DELETE /admin/licenses/{id}", s.requireAdmin(s.handleDelete))
	mux.HandleFunc("POST /admin/licenses/{id}/revoke", s.requireAdmin(s.handleRevoke))
	mux.HandleFunc("POST /admin/licenses/{id}/restore", s.requireAdmin(s.handleRestore))
	mux.HandleFunc("POST /admin/licenses/{id}/extend", s.requireAdmin(s.handleExtend))
	mux.HandleFunc("POST /admin/licenses/{id}/update", s.requireAdmin(s.handleUpdate))
	mux.HandleFunc("POST /admin/licenses/{id}/features", s.requireAdmin(s.handleUpdateFeatures))
	mux.HandleFunc("DELETE /admin/licenses/{id}/machines", s.requireAdmin(s.handleUnbindAll))
	mux.HandleFunc("DELETE /admin/licenses/{id}/machines/{mhash}", s.requireAdmin(s.handleKick))

	// 中间件链: 外层 recover → 访问日志 → CORS → 体积上限 → 每 IP 限流(仅 /v1/*).
	var h http.Handler = mux
	h = withRateLimit(h, "/v1/", s.limiter)
	h = withBodyLimit(h, maxBodyBytes)
	h = withCORS(h)
	h = withRequestLogging(h)
	h = withRecover(h)
	return h
}
