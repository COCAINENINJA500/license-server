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

// promptHead 是给 Coding Agent 的任务提示词头部;完整提示词 = 头部 + 对接文档全文.
const promptHead = `# 任务:为当前项目实现 License 客户端授权模块

你是一名资深后端工程师。请先通读文末的《License Server 对接文档》(由服务端实时生成,内嵌真实公钥与有效期参数),然后为当前项目实现完整、可直接编译运行的客户端授权模块。

## 实现要求

1. **本地验签**:把文档中的公钥(PUBKEY_B64,EdDSA/Ed25519)内置进客户端。校验 access JWT 的签名、iss、typ=access、exp;离线状态同样可信。读取 claims.features 作为功能开关与配额。
2. **machine_hash**:取设备稳定标识(主板序列号 / 磁盘序列号 / 机器 GUID 等)拼接后做 SHA256,输出小写 hex;重启、重装后必须保持稳定。
3. **激活**:首次运行调用 POST /v1/activate(license_key、machine_hash、timestamp、nonce)。license_key 从配置或环境变量读取,不硬编码。
4. **续期**:access 剩余有效期不足一半时,后台调用 POST /v1/refresh。每次响应都会返回新的 refresh_token,必须覆盖保存——旧 token 已被服务端作废,重用会得到 401。
5. **失败语义**:refresh 返回 401/403 = 授权失效(吊销 / 过期 / 超席位 / 被踢),停止受保护功能并提示用户续费;网络异常时凭未过期 access 离线运行至 exp。
6. **防重放**:timestamp = 当前 Unix 秒(注意校时);nonce 每次全新随机(8~128 位 [A-Za-z0-9-_])。
7. **安全**:Admin Key 与客户端无关,严禁打包;token 持久化文件设置安全权限;全部网络请求设置超时。
8. **交付**:完整可编译代码 + 在当前项目中的挂载点说明 + 单元测试(验签与激活/续期状态机)。若当前项目上下文不足以确定语言与框架,先向我提问再动手。

---

# 《License Server 对接文档》

`

// IntegrationPrompt 生成可直接复制给 Coding Agent 的完整提示词(任务要求 + 对接文档全文).
func IntegrationPrompt(pub ed25519.PublicKey, accessTTL, refreshTTL time.Duration) string {
	return promptHead + IntegrationMarkdown(pub, accessTTL, refreshTTL)
}
