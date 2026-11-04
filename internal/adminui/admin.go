// Package adminui 内嵌单租户管理台(单文件 HTML,零外部依赖、零 CDN)与
// 实时生成的对接文档. 随二进制发布.
package adminui

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

//go:embed admin.html
var adminHTML string

//go:embed integration.md
var integrationDoc string

// HTMLHandler 返回管理台页面.
func HTMLHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(adminHTML))
	}
}

// IntegrationMarkdown 生成对接文档,内嵌当前实例真实公钥与有效期参数.
func IntegrationMarkdown(pub ed25519.PublicKey, accessTTL, refreshTTL time.Duration) string {
	return strings.NewReplacer(
		"{{PUBKEY_B64}}", base64.StdEncoding.EncodeToString(pub),
		"{{PUBKEY_HEX}}", hex.EncodeToString(pub),
		"{{ACCESS_TTL}}", accessTTL.String(),
		"{{REFRESH_TTL}}", refreshTTL.String(),
	).Replace(integrationDoc)
}
