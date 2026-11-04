# 轻量云端 License 鉴权系统

[![CI](https://github.com/COCAINENINJA500/ed25519-license-server/actions/workflows/ci.yml/badge.svg)](https://github.com/COCAINENINJA500/ed25519-license-server/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)

单二进制、无 CGO、零外部服务依赖：SQLite 本地文件即数据库，开箱即用。
给自己的软件加一个”受控分发”能力：签发 license → 客户端激活绑定设备 → 靠短期 access JWT + 后台 refresh 续期，吊销/过期/超席位全部卡在 refresh。

## 对原需求的取舍说明

原需求几乎全盘接受，只做了三处最小补强（都是为了让“吊销与续费的唯一卡点”真正成立）：

1. **多了 `POST /admin/licenses/{id}/extend`（续期）**——续费必须有个地方把 `expires_at` 往后拨，否则 refresh 永远无法恢复，只是把“收费动作”留在系统外，鉴权侧只调这个接口。
2. **多了 `DELETE /admin/licenses/{id}/machines/{mhash}`（踢设备/释放席位）**——换机、设备丢失是分发刚需；被踢设备下次 refresh 即被拒绝（最长延迟 1 个 access 有效期）。
3. **refresh 每次轮换**：`POST /v1/refresh` 同时返回新 access + 新 refresh；`access.exp = min(现在+24h, license 到期)`，断网可凭未过期 access 继续用（天然离线宽限，上限 24h，可用 `--access-ttl` 调整）。

其余严格按需求实现：key 只存 SHA256、两张表、timestamp±5min + nonce 内存去重 10min、全程 TLS（直连用 `--tls-cert/--tls-key`，或放反向代理后）。

不做的：账号体系、支付、多租户 UI。

## 安全与健壮性设计

- **refresh 轮换 + 重用检测**：每次 refresh 轮换 refresh token，库中记录当前 `jti`；被轮换的旧 token 再次出现即 `401` 立即作废（防盗用，见 `activations.current_refresh_jti`）。
- **每 IP 限流**：`/v1/*` token bucket（默认 1 rps / burst 10，`--rate-rps/--rate-burst` 可调，`--rate-rps 0` 关闭），反代场景自动读取 `X-Forwarded-For`。
- **请求体上限**：统一 1 MiB，超限 `413`。
- **优雅停机**：SIGINT/SIGTERM 后 10s 排水在途请求；`http.Server` 全套超时（Slowloris 防护）。
- **防重放**：activate/refresh 强制 `timestamp`（±5 分钟）+ `nonce`（双代内存去重，O(1) 清理）。
- **panic 隔离**：单个请求 panic 不击穿进程，统一转 500 并记录堆栈。

## 目录结构

```
.
├── cmd/license-server/     # 入口：flag 解析、依赖装配、http.Server、优雅停机
├── internal/
│   ├── config/             # 配置（flag 与环境变量等价，flag 优先）
│   ├── store/              # SQLite 持久层：建表/迁移 + 全部查询（ctx 透传）
│   ├── licensing/          # Ed25519 密钥、JWT 签发/校验、防重放 nonce
│   ├── api/                # 客户端 + 管理 API、中间件（日志/限流/CORS/体积上限/recover）
│   └── adminui/            # go:embed 内嵌管理台 HTML 与对接文档模板
├── .github/workflows/ci.yml
├── Dockerfile
├── Makefile
└── main→cmd 单测试覆盖见 internal/api/server_test.go
```

## 快速开始

```bash
# 构建（单二进制，约 16MB；version 注入 git describe）
make build   # 或: CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always)" -o license-server ./cmd/license-server

# 启动（首次自动生成 admin key + Ed25519 签名密钥并打印）
./license-server --addr :8080 --db licenses.db

# 生产建议用环境变量固定密钥
LICENSE_ADMIN_KEY=<强随机串> ./license-server --addr :8080 --db /data/licenses.db \
  --tls-cert /etc/ssl/server.crt --tls-key /etc/ssl/server.key
```

Docker（静态编译 + distroless 非 root 镜像）：

```bash
docker build -t ed25519-license-server .
docker run -d -p 8080:8080 -v license-data:/data ed25519-license-server
curl http://127.0.0.1:8080/healthz   # {"status":"ok","version":"..."}
```

常用配置（flag 与环境变量等价，flag 优先）：

| flag | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `--addr` | `LICENSE_ADDR` | `:8080` | 监听地址 |
| `--db` | `LICENSE_DB` | `licenses.db` | SQLite 文件路径（自动建表） |
| `--admin-key` | `LICENSE_ADMIN_KEY` | 自动生成 | 管理 API 的 Bearer Key |
| `--privkey` | `LICENSE_PRIVKEY` | `license_ed25519.key` | Ed25519 私钥文件（hex seed，不存在则生成） |
| `--access-ttl` | `LICENSE_ACCESS_TTL` | `24h` | access JWT 有效期 = 离线宽限上限 |
| `--refresh-ttl` | `LICENSE_REFRESH_TTL` | `720h` | refresh 有效期（30 天） |
| `--tls-cert/--tls-key` | `LICENSE_TLS_CERT/KEY` | 空（明文，仅开发） | 生产必须配置或走反向代理 |

公钥获取（随客户端发布，客户端只认这个公钥验签）：

```bash
curl http://127.0.0.1:8080/v1/pubkey
# {"alg":"EdDSA","pubkey_b64":"...","pubkey_hex":"..."}
```

## 管理台（单租户内嵌 UI）

浏览器打开 `http://127.0.0.1:8080/admin`（或 `https://你的域名/admin`），先过登录门禁：输入 Admin Key，后端用管理接口实地验签，通过才进入管理台（Key 仅存本浏览器 localStorage，可退出清除）。未登录只能看到登录卡，看不到任何操作区。

管理台是内嵌的**多页面 SPA**（hash 路由，顶栏切换，黑白中性色 / 支持深色模式）：

- **概览**：统计卡（总数/有效/即将到期/已过期/已吊销/席位占用）+ 最近签发
- **台账**：服务端分页表格（搜索、状态筛选、列排序、每页条数），行内操作
- **接入指南**：一键下载 `GET /admin/integration.md`（内嵌本实例真实公钥，直接给其他 Coding Agent）、公钥展示、`features` 说明

操作涵盖：签发（`license_key` 明文只显示一次，带一键复制）、详情（设备列表）、续期、编辑功能标记、吊销/恢复、踢设备、**彻底删除**。

单文件 HTML（含 CSS/JS，零外部依赖、无 CDN）打进同一二进制，无账号体系、无多租户概念。日常用它，脚本批量操作走下面的管理 API。

## API 一览

管理 API（一律 `Authorization: Bearer <ADMIN_KEY>`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/admin/licenses` | 签发，body `{"customer","days","seats","features"}`，`license_key` 明文仅返回一次 |
| `GET` | `/admin/licenses` | 分页列出台账，query `q`（客户/ID 模糊）、`status`（`all`/`active`/`expiring`/`expired`/`revoked`）、`page`、`page_size`(≤100)、`sort`、`order`；返回 `{licenses,total,page,page_size,total_pages}` |
| `GET` | `/admin/stats` | 汇总统计（总数/有效/即将到期/已过期/已吊销/席位占用） |
| `GET` | `/admin/licenses/{id}` | 查询单个 + 设备列表 |
| `POST` | `/admin/licenses/{id}/revoke` | 吊销（保留台账） |
| `POST` | `/admin/licenses/{id}/restore` | 恢复已吊销 |
| `POST` | `/admin/licenses/{id}/extend` | 续期，body `{"add_days":30}` |
| `POST` | `/admin/licenses/{id}/update` | 修改客户名/席位数，body `{"customer","seats"}`（可只传其一；下调席位后超额设备下次 refresh 被拒） |
| `POST` | `/admin/licenses/{id}/features` | 修改功能标记，body `{"features":{...}}`（客户端下次 refresh 生效） |
| `DELETE` | `/admin/licenses/{id}` | **彻底删除**该 license 及其全部设备记录（不可恢复，可删已吊销的） |
| `DELETE` | `/admin/licenses/{id}/machines` | 解绑全部设备，释放席位 |
| `DELETE` | `/admin/licenses/{id}/machines/{mhash}` | 踢单台设备，释放席位 |

> 图形操作见上面的管理台（`GET /admin`，同样单二进制内嵌）。

客户端 API：

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/v1/activate` | `license_key + machine_hash + timestamp + nonce` → access + refresh |
| `POST` | `/v1/refresh` | `refresh_token + timestamp + nonce` → 新 access + 轮换 refresh |
| `GET` | `/v1/status` | Bearer access 查到期信息；或 `?license_key=..&machine_hash=..` 查台账摘要 |
| `GET` | `/v1/pubkey` | 取 Ed25519 公钥 |
| `GET` | `/healthz` | 健康检查 |

错误码约定：`400` 参数/时间窗/nonce 格式问题，`401` key 或 token 无效，`403` 已吊销/已过期/席位已满/设备已解绑，`409` nonce 重放。

## curl 全流程示例

以下假设服务端在 `https://lic.example.com`，管理 key 为 `$ADMIN`。

```bash
# 1. 签发（客户 Acme，有效 365 天，5 席位，功能标记为任意 JSON）
curl -s https://lic.example.com/admin/licenses \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" -d '{
    "customer": "Acme",
    "days": 365,
    "seats": 5,
    "features": {"pro": true, "level": "vip", "max_projects": 20}
  }'
# -> {"license_id":"...","license_key":"LIC-...","expires_at":...,"features":{...},"status":"active"}
#    注意：license_key 明文只出现这一次，请妥善发给客户。

# 2. 列出台账 / 查询单个
curl -s https://lic.example.com/admin/licenses -H "Authorization: Bearer $ADMIN"
curl -s https://lic.example.com/admin/licenses/<license_id> -H "Authorization: Bearer $ADMIN"

# 3. 客户端激活（每台设备一次；machine_hash 建议取设备稳定标识的 SHA256 hex）
TS=$(date +%s); NONCE=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)
MACHINE=$(echo -n "my-device-serial-001" | sha256sum | cut -d' ' -f1)
curl -s https://lic.example.com/v1/activate \
  -H "Content-Type: application/json" -d "{
    \"license_key\": \"LIC-...发给客户的key...\",
    \"machine_hash\": \"$MACHINE\",
    \"timestamp\": $TS,
    \"nonce\": \"$NONCE\"
  }"
# -> {"access_token":"eyJ...","refresh_token":"eyJ...","expires_in":86400,
#     "access_expires_at":...,"license_expires_at":...,"features":{...}}

# 4. 用 refresh 换新 access（建议在 access 过期前一半时间后台执行；每次返回新的 refresh，请覆盖保存）
TS=$(date +%s); NONCE=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)
curl -s https://lic.example.com/v1/refresh \
  -H "Content-Type: application/json" -d "{
    \"refresh_token\": \"$REFRESH\",
    \"timestamp\": $TS,
    \"nonce\": \"$NONCE\"
  }"

# 5. 查询剩余有效期（推荐用 access token，不暴露 license_key）
curl -s https://lic.example.com/v1/status -H "Authorization: Bearer $ACCESS"
# -> {"valid":true,"license_id":"...","token_expires_at":...,"license_expires_at":...,"features":{...}}

# 6. 吊销（下一轮 refresh 即失效，最长延迟 1 个 access 有效期；要立即踢下线需客户端缩短 access-ttl 或主动校验）
curl -s -X POST https://lic.example.com/admin/licenses/<license_id>/revoke \
  -H "Authorization: Bearer $ADMIN"

# 7. 续费（把到期时间往后拨 30 天；已过期的从现在起算）
curl -s -X POST https://lic.example.com/admin/licenses/<license_id>/extend \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"add_days": 30}'

# 8. 换机/释放席位（踢掉旧设备，席位立即释放；旧设备下次 refresh 被拒）
curl -s -X DELETE https://lic.example.com/admin/licenses/<license_id>/machines/$MACHINE \
  -H "Authorization: Bearer $ADMIN"
```

`timestamp` 为 Unix 秒，`nonce` 为 8~128 位 `[A-Za-z0-9-_]` 随机串，每次请求必须全新。

## 客户端集成伪代码

客户端只做两件事：**本地验 access 签名** + **过期前后台 refresh**。断网时凭未过期 access 继续用（上限 24h，可配）。

```python
import time, json, hashlib, secrets, requests
import jwt  # PyJWT，需支持 EdDSA；或用 libsodium/ed25519 自行验签

SERVER = "https://lic.example.com"
PUBKEY_B64 = "..."           # 发布时嵌入：GET /v1/pubkey 取到的 pubkey_b64
LICENSE_KEY = "LIC-..."      # 随软件分发给客户
STORE = "./license_tokens.json"  # 安全保存 access/refresh 的位置

def machine_hash():
    raw = platform.node() + "-" + disk_serial() + "-" + cpu_id()
    return hashlib.sha256(raw.encode()).hexdigest()

def call_activate():
    body = {"license_key": LICENSE_KEY, "machine_hash": machine_hash(),
            "timestamp": int(time.time()), "nonce": secrets.token_urlsafe(18)}
    r = requests.post(SERVER + "/v1/activate", json=body, timeout=10)
    r.raise_for_status()
    save(STORE, r.json())

def call_refresh(refresh_token):
    body = {"refresh_token": refresh_token,
            "timestamp": int(time.time()), "nonce": secrets.token_urlsafe(18)}
    r = requests.post(SERVER + "/v1/refresh", json=body, timeout=10)
    if r.status_code in (401, 403):
        raise LicenseInvalid("被吊销/过期/超席位/被踢，需客户联系续费")
    r.raise_for_status()
    save(STORE, r.json())   # 注意覆盖保存新的 refresh_token

def get_valid_access():
    toks = load(STORE)
    if toks is None:
        return call_activate()  # 首 run
    try:
        # 本地验签 + 检查 exp（断网也能做）
        claims = jwt.decode(toks["access_token"], PUBKEY_B64, algorithms=["EdDSA"])
        if claims["exp"] - time.time() < 6 * 3600:
            # 过期前 6h 后台续期；失败且 access 仍有效则继续用（离线宽限）
            try: call_refresh(toks["refresh_token"])
            except LicenseInvalid: raise
            except Exception: pass  # 网络问题：凭旧 access 撑到 exp
            toks = load(STORE)
        return toks["access_token"], claims["features"]
    except jwt.ExpiredSignatureError:
        # access 已过期：必须在线 refresh
        call_refresh(toks["refresh_token"])
        toks = load(STORE)
        return toks["access_token"], decode_features(toks["access_token"])
```

要点：

- `machine_hash` 用稳定设备标识的 SHA256，同一设备重装/重启保持不变。
- `features` 从 access JWT 里读（服务端已签名，本地可信），做功能开关。
- refresh 失败分两类：`401/403` = license 层失效（弹窗提示联系续费）；网络异常 = 凭旧 access 撑到 `exp`。
- 公钥随版本发布；轮换密钥时需发新版客户端（或做多公钥兼容）。

## 数据模型（仅两张表）

```sql
licenses(id, key_hash UNIQUE, customer, seats, expires_at, features, status, created_at)
-- key_hash = SHA256 hex(license_key)，库里永远没有明文 key
activations(license_id, machine_hash, first_seen, last_seen, current_refresh_jti, PRIMARY KEY(license_id, machine_hash))
```

- refresh token 为自包含 JWT（`typ=refresh`，内含 license_id + machine_hash），无需落库，所以两张表足够。
- 席位语义：`activations` 行数 ≤ `seats`；同机重复激活幂等（更新 `last_seen`，不占新席位）。
- `current_refresh_jti` 记录每台设备当前有效的 refresh token；轮换出的旧 token 重用即 401。

## 安全说明

- 全程 TLS：直连用 `--tls-cert/--tls-key`，或放 Caddy/Nginx 后面；`GET /v1/status?license_key=` 会进访问日志，敏感环境请用 Bearer 模式。
- 防重放：activate/refresh 强制 `timestamp`（±5min，客户端请做 NTP/校时）+ `nonce`（服务端双代内存去重 10min，复用返回 409）。多实例部署需把 nonce 去重外置（如 Redis），单实例默认内存即可。
- refresh 轮换重用检测：旧 refresh 再次出现立即 401；`401`（重用/无效）与 `403`（吊销/过期/超席位/被踢）语义不同，客户端据此区分处理。
- 服务端只存 key 的 SHA256；签名密钥（Ed25519）文件权限 0600 且不入库（.gitignore），泄露需轮换并重新签发客户端公钥。
- 本系统不做防共享（同一 key 多人共用同一 machine_hash 无法识别），强绑定场景请结合硬件指纹 + 小席位数 + 短 access-ttl。

## 测试

```bash
go test -race ./...
# 或 make test
```

覆盖：签发→激活→JWT 可验、超席位 403、同机幂等、吊销后 refresh/激活 403、过期后 refresh 403（续期后恢复）、**轮换重用 401**、nonce 重放 409、时间窗外 400、**限流 429**、**请求体超限 413**、管理鉴权 401、踢设备后 refresh 403、管理台页面 200 + 列表接口、对接文档内嵌真实公钥、密钥文件生成/加载、nonce 双代清理。

## License

[Apache-2.0](LICENSE) © 2026 n0way10se
