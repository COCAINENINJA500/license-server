<div align="center">

# license-server

**轻量云端 License 鉴权服务端**

Ed25519 签名 access JWT · 设备绑定席位 · refresh 轮换与重用检测 · SQLite 单文件 · 单二进制零 CGO

[![CI](https://github.com/COCAINENINJA500/license-server/actions/workflows/ci.yml/badge.svg)](https://github.com/COCAINENINJA500/license-server/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/COCAINENINJA500/license-server)](https://goreportcard.com/report/github.com/COCAINENINJA500/license-server)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

[特性](#-特性) · [工作原理](#-工作原理) · [快速开始](#-快速开始) · [API](#-api-一览) · [部署](#-部署) · [安全设计](#-安全设计)

</div>

---

## 为什么需要它

给自己的软件加一层"受控分发"：签发 license → 客户端激活绑定设备 → 短期 access JWT 本地验签，后台 refresh 续期——**吊销、过期、超席位、踢设备，全部卡在 refresh 这一个 chokepoint 上**。断网凭未过期 access 离线宽限（上限可配），在线即刻执行管理策略。

- 服务端只有一个二进制 + 一个 SQLite 文件，`docker run` 即上生产
- 客户端只需内置**公钥**，永远不碰 Admin Key
- 内嵌单租户管理台 SPA，零 CDN、零账号体系

## ✨ 特性

| | |
|---|---|
| 🔐 **Ed25519 / EdDSA** | access JWT 服务端签名，客户端公钥本地验签，断网可信 |
| 🪑 **席位制设备绑定** | `machine_hash` 维度绑定，同机重复激活幂等，超席位 403 |
| 🔄 **refresh 轮换 + 重用检测** | 每次续期换发新 refresh；被轮换的旧 token 再次出现立即 `401`（防盗用） |
| 🛡 **防重放** | `timestamp` ±5 分钟 + `nonce` 双代内存去重（O(1) 清理），复用 `409` |
| 🖥 **内嵌管理台** | 单文件 HTML SPA 打进二进制：概览 / 台账 / 产品模板 / 签发 / 续期 / 吊销 / 踢设备 |
| 🚦 **内置防御** | 每 IP 限流（429）、请求体 1 MiB 上限（413）、全套 HTTP 超时、panic 隔离 |
| 📦 **交付友好** | 零 CGO 静态编译、WAL SQLite、distroless 非 root 容器、`/healthz` 带版本号 |

## 🔎 工作原理

```text
        管理端 (Admin Key)                    服务端                              客户端 (仅公钥)
             │                                 │                                    │
             │  POST /admin/licenses           │                                    │
             │────────────────────────────────▶│ 签发：库中只存 SHA256(key)          │
             │◀──── license_key（仅此一次）─────│                                    │
             │                                 │        license_key 随软件分发 ────▶│
             │                                 │  POST /v1/activate                 │
             │                                 │◀────────────────────────────────────│ 绑定设备
             │                                 │──── access + refresh ─────────────▶│ 本地验签
             │                                 │  POST /v1/refresh（后台自动）       │
             │                                 │◀────────────────────────────────────│ 轮换续期
             │  POST .../revoke                │                                    │
             │────────────────────────────────▶│──── 下次 refresh 403 ─────────────▶│ 提示续费
```

吊销 / 过期 / 超席位 / 被踢全部在 refresh 拒绝——最长延迟 = 1 个 access 有效期（离线宽限上限）。

## 🚀 快速开始

### 源码

```bash
# 构建（version 注入 git describe）
make build   # 或: CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always)" -o license-server ./cmd/license-server

# 启动（首次自动生成 admin key + Ed25519 签名密钥并打印）
./license-server --addr :8080 --db licenses.db
```

### Docker

```bash
docker build -t license-server .
docker run -d -p 8080:8080 -v license-data:/data license-server
curl http://127.0.0.1:8080/healthz
# {"status":"ok","version":"..."}
```

> [!WARNING]
> 生产环境请全程 TLS：直连用 `--tls-cert/--tls-key`，或放在 Caddy/Nginx 反向代理之后。明文 HTTP 仅限本地开发。

常用配置（flag 与环境变量等价，flag 优先）：

| flag | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `--addr` | `LICENSE_ADDR` | `:8080` | 监听地址 |
| `--db` | `LICENSE_DB` | `licenses.db` | SQLite 文件路径（自动建表迁移） |
| `--admin-key` | `LICENSE_ADMIN_KEY` | 自动生成 | 管理 API 的 Bearer Key |
| `--privkey` | `LICENSE_PRIVKEY` | `license_ed25519.key` | Ed25519 私钥文件（hex seed，自动生成 0600） |
| `--access-ttl` | `LICENSE_ACCESS_TTL` | `24h` | access JWT 有效期 = 离线宽限上限 |
| `--refresh-ttl` | `LICENSE_REFRESH_TTL` | `720h` | refresh token 有效期（30 天） |
| `--rate-rps` | `LICENSE_RATE_RPS` | `1` | `/v1/*` 每 IP 限流（0 关闭；反代自动读 `X-Forwarded-For`） |
| `--rate-burst` | `LICENSE_RATE_BURST` | `10` | 每 IP 突发容量 |
| `--tls-cert/--tls-key` | `LICENSE_TLS_CERT/KEY` | 空 | 生产必须配置或走反向代理 |

## 🖥 管理台（单租户内嵌 UI）

浏览器打开 `http://127.0.0.1:8080/admin`：输入 Admin Key 登录（后端实地验签，Key 仅存本浏览器 localStorage）。未登录只能看到登录卡，无任何操作区。

内嵌多页面 SPA（hash 路由，黑白中性色 + 深色模式）：

- **概览**：统计卡（总数 / 有效 / 即将到期 / 已过期 / 已吊销 / 席位占用）+ 最近签发
- **台账**：服务端分页表格（搜索、状态筛选、列排序、每页条数），整行点击进详情
- **产品**：维护产品模板（功能标记 + 默认天数 / 席位），签发时选择产品自动带入
- **接入指南**：一键**复制 AI 对接提示词**（内嵌本实例真实公钥，粘贴给任意 Coding Agent 即可开工）、下载 Markdown 文档、公钥展示、features 说明

操作涵盖：签发（`license_key` 明文只显示一次）、详情（设备列表）、续期、编辑功能标记、吊销 / 恢复、踢设备、彻底删除。

## 📡 API 一览

管理 API（一律 `Authorization: Bearer <ADMIN_KEY>`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/admin/licenses` | 签发，body `{"customer","product_id"?,"days"?,"seats"?,"features"?}`——带 `product_id` 时未提供的字段自动取产品默认值；`license_key` 明文仅返回一次 |
| `GET` | `/admin/licenses` | 分页列表，query `q`（客户/ID 模糊）、`status`（`all`/`active`/`expiring`/`expired`/`revoked`）、`page`、`page_size`(≤100)、`sort`、`order` |
| `GET` | `/admin/stats` | 汇总统计 |
| `GET` | `/admin/licenses/{id}` | 查询单个 + 设备列表 |
| `POST` | `/admin/licenses/{id}/revoke` | 吊销（保留台账） |
| `POST` | `/admin/licenses/{id}/restore` | 恢复已吊销 |
| `POST` | `/admin/licenses/{id}/extend` | 续期，body `{"add_days":30}` |
| `POST` | `/admin/licenses/{id}/update` | 修改客户名/席位数（可只传其一；下调席位后超额设备下次 refresh 被拒） |
| `POST` | `/admin/licenses/{id}/features` | 修改功能标记（客户端下次 refresh 生效） |
| `DELETE` | `/admin/licenses/{id}` | **彻底删除**该 license 及全部设备记录（不可恢复） |
| `DELETE` | `/admin/licenses/{id}/machines` | 解绑全部设备，释放席位 |
| `DELETE` | `/admin/licenses/{id}/machines/{mhash}` | 踢单台设备，释放席位 |

产品目录（签发侧模板，管理 license 时选择产品自动带入默认配置；产品变更不影响已签发 license 的快照）：

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/admin/products` | 新增产品，body `{"name","features","default_days","default_seats"}`（重名 409） |
| `GET` | `/admin/products` | 产品列表 |
| `POST` | `/admin/products/{id}/update` | 修改产品（可只传部分字段） |
| `DELETE` | `/admin/products/{id}` | 删除产品（已签发 license 不受影响） |

客户端 API：

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/v1/activate` | `license_key + machine_hash + timestamp + nonce` → access + refresh |
| `POST` | `/v1/refresh` | `refresh_token + timestamp + nonce` → 新 access + 轮换 refresh |
| `GET` | `/v1/status` | Bearer access 查到期信息；或 `?license_key=..&machine_hash=..` 查台账摘要 |
| `GET` | `/v1/pubkey` | 取 Ed25519 公钥 |
| `GET` | `/healthz` | 健康检查（含版本号） |

错误码约定：`400` 参数/时间窗/nonce 格式 · `401` key 或 token 无效 / refresh 重用 · `403` 已吊销/已过期/席位已满/设备已解绑 · `409` nonce 重放 · `413` 请求体超限 · `429` 触发限流。

## 🧪 curl 全流程示例

假设服务端在 `https://lic.example.com`，管理 key 为 `$ADMIN`。

```bash
# 1. 签发（客户 Acme，365 天，5 席位，features 为任意 JSON）
curl -s https://lic.example.com/admin/licenses \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" -d '{
    "customer": "Acme", "days": 365, "seats": 5,
    "features": {"pro": true, "level": "vip", "max_projects": 20}
  }'
# -> {"license_id":"...","license_key":"LIC-...","expires_at":...}
#    license_key 明文只出现这一次，请妥善发给客户。

# 2. 客户端激活（machine_hash 建议取设备稳定标识的 SHA256 hex）
TS=$(date +%s); NONCE=$(openssl rand -hex 12)
MACHINE=$(echo -n "my-device-serial-001" | sha256sum | cut -d' ' -f1)
curl -s https://lic.example.com/v1/activate -H "Content-Type: application/json" -d "{
  \"license_key\": \"LIC-...\", \"machine_hash\": \"$MACHINE\",
  \"timestamp\": $TS, \"nonce\": \"$NONCE\"
}"
# -> {"access_token":"eyJ...","refresh_token":"eyJ...",...}

# 3. 用 refresh 换新 access（建议过期前一半时间后台执行；每次轮换，覆盖保存）
TS=$(date +%s); NONCE=$(openssl rand -hex 12)
curl -s https://lic.example.com/v1/refresh -H "Content-Type: application/json" -d "{
  \"refresh_token\": \"$REFRESH\", \"timestamp\": $TS, \"nonce\": \"$NONCE\"
}"

# 4. 查询剩余有效期（推荐 access token，不暴露 license_key）
curl -s https://lic.example.com/v1/status -H "Authorization: Bearer $ACCESS"

# 5. 吊销 / 续费 / 踢设备
curl -s -X POST https://lic.example.com/admin/licenses/<id>/revoke  -H "Authorization: Bearer $ADMIN"
curl -s -X POST https://lic.example.com/admin/licenses/<id>/extend  -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" -d '{"add_days": 30}'
curl -s -X DELETE https://lic.example.com/admin/licenses/<id>/machines/$MACHINE -H "Authorization: Bearer $ADMIN"
```

`timestamp` 为 Unix 秒；`nonce` 为 8~128 位 `[A-Za-z0-9-_]` 随机串，每次请求必须全新。

## 🐍 客户端集成（伪代码）

客户端只做两件事：**本地验 access 签名** + **过期前后台 refresh**。断网时凭未过期 access 继续用（上限 24h，可配）。

```python
def machine_hash():
    raw = platform.node() + "-" + disk_serial() + "-" + cpu_id()
    return hashlib.sha256(raw.encode()).hexdigest()

def get_valid_access():
    toks = load(STORE)
    if toks is None:
        return call_activate()                 # 首次运行
    claims = jwt.decode(toks["access_token"], PUBKEY_B64, algorithms=["EdDSA"])
    if claims["exp"] - time.time() < 6 * 3600: # 剩余 < 6h 后台续期
        try:
            call_refresh(toks["refresh_token"])    # 轮换：覆盖保存新 refresh
        except LicenseInvalid:
            raise                                  # 401/403 = 被吊销/过期/超席位/被踢
        except Exception:
            pass                                   # 网络异常：凭旧 access 撑到 exp
    return toks["access_token"], claims["features"]
```

要点：

- `features` 从 access JWT 里读（服务端已签名，本地可信），做功能开关与配额。
- `401`（token 无效 / 轮换重用）与 `403`（吊销 / 过期 / 超席位 / 被踢）语义不同，客户端据此区分提示。
- 公钥随版本发布；轮换密钥时需发新版客户端（或多公钥兼容）。

## 🗃 数据模型（仅两张表）

```sql
licenses(id, key_hash UNIQUE, customer, seats, expires_at, features, status, created_at)
-- key_hash = SHA256 hex(license_key)，库里永远没有明文 key
activations(license_id, machine_hash, first_seen, last_seen, current_refresh_jti,
            PRIMARY KEY(license_id, machine_hash))
products(id, name UNIQUE, features, default_days, default_seats, created_at)
-- 产品是签发侧模板:签发时把产品的 features / 默认值复制进 license,此后两者互不影响
```

- refresh token 是自包含 JWT（`typ=refresh`，内含 license_id + machine_hash），无需落库，两张表足够。
- 席位语义：`activations` 行数 ≤ `seats`；同机重复激活幂等（更新 `last_seen`，不占新席位）。
- `current_refresh_jti` 记录每台设备当前有效的 refresh；轮换出的旧 token 重用即 401。

## 🛡 安全设计

- **全程 TLS**：直连 `--tls-cert/--tls-key` 或反代；`?license_key=` 会进访问日志，敏感环境用 Bearer 模式。
- **防重放**：`timestamp` ±5min（客户端做校时）+ `nonce` 双代去重 10min（复用 409）。多实例部署需外置 nonce 去重（如 Redis）。
- **轮换重用检测**：被轮换的旧 refresh 再次出现立即 401——即使它本身尚未过期。
- **密钥管理**：服务端只存 key 的 SHA256；签名私钥文件 0600 且被 .gitignore 排除，泄露需轮换并重新发布客户端公钥。
- **输入面收敛**：全部查询参数化、排序字段白名单、body 1 MiB、每 IP 限流、管理鉴权常数时间比较。
- 本系统不做防共享（同 key 同 machine_hash 无法识别共用），强绑定场景结合硬件指纹 + 小席位 + 短 access-ttl。

## 🧪 测试

```bash
go test -race ./...    # 或 make test
```

覆盖：签发→激活→JWT 验签、超席位 403、同机幂等、吊销后 refresh/激活 403、过期后 refresh 403（续期恢复）、**轮换重用 401**、nonce 重放 409、时间窗外 400、**限流 429**、**请求体超限 413**、管理鉴权 401、踢设备后 refresh 403、管理台页面、对接文档内嵌真实公钥、密钥文件生成/加载、nonce 代际清理。

## 📄 License

[Apache-2.0](LICENSE) © 2026 n0way10se
