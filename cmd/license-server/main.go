// Command license-server 是一个轻量通用云端 License 鉴权服务端.
//
// 特性:
//   - 单二进制、无 CGO (modernc.org/sqlite)、零外部服务依赖,SQLite 本地文件即数据库
//   - 管理 API (Bearer Key 鉴权):签发 / 查询 / 列出 / 吊销 / 恢复 / 续期 / 踢设备
//   - 客户端 API: activate / refresh / status, access JWT(Ed25519, 默认 24h) + refresh JWT(默认 30 天)
//   - refresh 轮换 + 重用检测:被轮换的旧 refresh 立即作废
//   - 防重放: activate/refresh 必须带 timestamp(±5 分钟) + nonce(内存去重 10 分钟)
//   - 数据模型仅两张表: licenses 与 activations, license_key 只存 SHA256 哈希
//
// 运行:
//
//	go run ./cmd/license-server --addr :8080 --db licenses.db
//	LICENSE_ADMIN_KEY=xxx go run ./cmd/license-server --addr :8080
//
// 生产环境请全程 TLS: 直接 --tls-cert/--tls-key,或放在反向代理(Caddy/Nginx)后面.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/COCAINENINJA500/ed25519-license-server/internal/api"
	"github.com/COCAINENINJA500/ed25519-license-server/internal/config"
	"github.com/COCAINENINJA500/ed25519-license-server/internal/licensing"
	"github.com/COCAINENINJA500/ed25519-license-server/internal/store"
)

// version 由构建时 -ldflags "-X main.version=..." 注入.
var version = "dev"

func main() {
	cfg := config.Load(flag.CommandLine)
	flag.Parse()

	priv, err := licensing.LoadOrCreateKey(cfg.PrivKey)
	if err != nil {
		log.Fatalf("加载签名密钥失败: %v", err)
	}
	if cfg.AdminKey == "" {
		gen, err := licensing.GenerateAdminKey()
		if err != nil {
			log.Fatalf("生成 admin key 失败: %v", err)
		}
		cfg.AdminKey = gen
		log.Printf("注意: 未配置管理 Key,已自动生成(重启会变,生产请设置 LICENSE_ADMIN_KEY): %s", gen)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer st.Close()

	signer := licensing.NewSigner(priv, cfg.AccessTTL, cfg.RefreshTTL)
	nonces := licensing.NewNonceStore(licensing.NonceRetention, nil)
	srv := api.NewServer(st, signer, cfg.AdminKey, nonces, version, cfg.RateRPS, cfg.RateBurst)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("license-server 启动: addr=%s db=%s access_ttl=%s refresh_ttl=%s version=%s",
		cfg.Addr, cfg.DBPath, cfg.AccessTTL, cfg.RefreshTTL, version)

	// 优雅停机: SIGINT/SIGTERM 后停止接收新连接,给在途请求 10s 排水.
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Printf("收到退出信号,优雅停机中…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		close(done)
	}()

	var serveErr error
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("TLS 已启用(全程加密)")
		serveErr = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		log.Printf("警告: 当前为明文 HTTP,仅用于本地开发;生产请配置 --tls-cert/--tls-key 或放在反向代理后启用 HTTPS")
		serveErr = httpSrv.ListenAndServe()
	}
	<-done
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Fatalf("服务退出: %v", serveErr)
	}
	log.Printf("license-server 已退出")
}
