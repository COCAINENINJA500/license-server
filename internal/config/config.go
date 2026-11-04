// Package config 负责服务配置的解析:命令行 flag 与环境变量等价,flag 优先.
package config

import (
	"flag"
	"os"
	"time"
)

// Config 服务配置.
type Config struct {
	Addr       string
	DBPath     string
	AdminKey   string
	PrivKey    string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	TLSCert    string
	TLSKey     string
	RateRPS    float64 // /v1/* 每 IP 限流(请求/秒)
	RateBurst  int     // 每 IP 突发容量
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Load 从命令行 flag / 环境变量解析配置. fs 可为 nil(使用默认 CommandLine flag set),
// 传入自定义 FlagSet 便于测试.
func Load(fs *flag.FlagSet) *Config {
	if fs == nil {
		fs = flag.CommandLine
	}
	c := &Config{}
	fs.StringVar(&c.Addr, "addr", envOr("LICENSE_ADDR", ":8080"), "监听地址")
	fs.StringVar(&c.DBPath, "db", envOr("LICENSE_DB", "licenses.db"), "SQLite 文件路径")
	fs.StringVar(&c.AdminKey, "admin-key", envOr("LICENSE_ADMIN_KEY", ""), "管理 API 的 Bearer Key(为空则自动生成并打印)")
	fs.StringVar(&c.PrivKey, "privkey", envOr("LICENSE_PRIVKEY", "license_ed25519.key"), "Ed25519 私钥文件(hex seed)")
	defAccess, _ := time.ParseDuration(envOr("LICENSE_ACCESS_TTL", "24h"))
	if defAccess <= 0 {
		defAccess = 24 * time.Hour
	}
	defRefresh, _ := time.ParseDuration(envOr("LICENSE_REFRESH_TTL", "720h"))
	if defRefresh <= 0 {
		defRefresh = 30 * 24 * time.Hour
	}
	fs.DurationVar(&c.AccessTTL, "access-ttl", defAccess, "access JWT 有效期(离线宽限上限,可配)")
	fs.DurationVar(&c.RefreshTTL, "refresh-ttl", defRefresh, "refresh token 有效期")
	fs.StringVar(&c.TLSCert, "tls-cert", envOr("LICENSE_TLS_CERT", ""), "TLS 证书文件(为空则明文 HTTP,生产请配置)")
	fs.StringVar(&c.TLSKey, "tls-key", envOr("LICENSE_TLS_KEY", ""), "TLS 私钥文件")
	fs.Float64Var(&c.RateRPS, "rate-rps", 1, "/v1/* 每 IP 限流(请求/秒,0 关闭限流)")
	fs.IntVar(&c.RateBurst, "rate-burst", 10, "/v1/* 每 IP 突发容量")
	return c
}
