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
// 写法上不做人设铺垫,直接给上下文,并按文档章节名引用,Agent 可按节检索.
const promptHead = `# 为当前项目实现 License 客户端授权模块

本项目按席位分发软件:客户端激活绑定设备,凭短期 access JWT 本地验签运行,后台 refresh 续期。鉴权服务已部署,完整接口契约与真实公钥见下文。

## 对接要点

- 激活与续期的请求/响应格式 → 参考「2. 客户端 API」
- machine_hash 生成规则 → 参考「4. machine_hash 生成」
- 调用时机与状态机 → 参考「5. 客户端状态机(推荐实现)」
- 失败分类与处理 → 参考「6. 错误码」
- 防重放参数(timestamp/nonce)→ 参考「3. 防重放」
- 密钥与部署边界 → 参考「8. 安全」

## 硬性要求

1. 将公钥 PUBKEY_B64 内置进客户端,本地验签 access JWT(EdDSA,校验签名 / iss / typ / exp),离线可信;读取 claims.features 作为功能开关与配额。
2. license_key 从配置或环境变量读取;Admin Key 严禁出现在客户端。
3. access 剩余有效期不足一半时后台调用 refresh;每次返回的新 refresh_token 必须覆盖保存——旧 token 已被服务端作废,重用会得到 401。
4. token 持久化文件设置安全权限;所有网络请求设置超时。
5. 交付完整可编译代码、在当前项目中的挂载点说明、单元测试(本地验签与激活/续期状态机)。
6. 若当前项目上下文不足以确定语言与框架,先向我提问再动手。

---
`

// IntegrationPrompt 生成可直接复制给 Coding Agent 的完整提示词(任务要点 + 对接文档全文).
// productName/productFeatures 非空时,注入"指定产品的功能标记"一节,Agent 按该产品实现开关.
func IntegrationPrompt(pub ed25519.PublicKey, accessTTL, refreshTTL time.Duration, productName, productFeatures string) string {
	out := promptHead
	if productName != "" {
		out += "## 指定产品的功能标记\n\n产品: " + productName + "\n\n```json\n" + productFeatures + "\n```\n\n客户端的功能开关语义以上述标记为准;未涉及的开关一律不要臆造。\n\n---\n\n"
	}
	out += IntegrationMarkdown(pub, accessTTL, refreshTTL)
	return out
}
