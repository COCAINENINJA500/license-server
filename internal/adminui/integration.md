# License Server 对接文档（面向 Coding Agent）

> 目标读者:需要把"受控分发/授权"接入本服务的客户端或后台开发 Agent。
> 本文档由服务端实时生成,其中的公钥与有效期参数即为当前实例真实值。

## TL;DR

- 客户端只做两件事:**本地验 access JWT 签名** + **过期前后台 refresh**。
- 激活用 license_key + machine_hash;之后用 refresh token 续期,refresh 每次轮换。
- 吊销 / 过期 / 超席位 / 被踢设备 全部在 refresh 被拒(最长延迟 1 个 access 有效期)。
- 客户端只需内置**公钥**,绝不需要、也不应内置 Admin Key。

## 1. 服务与公钥

| 项 | 值 |
| --- | --- |
| Base URL | https://<部署域名>（由部署方填写） |
| 签名算法 | EdDSA（Ed25519） |
| 公钥 base64 | {{PUBKEY_B64}} |
| 公钥 hex | {{PUBKEY_HEX}} |
| access JWT 有效期 | {{ACCESS_TTL}}（离线宽限上限） |
| refresh token 有效期 | {{REFRESH_TTL}} |

access JWT 主要 claim:

~~~json
{
  "iss": "license-server",
  "typ": "access",
  "sub": "<license_id>",
  "mhash": "<machine_hash>",
  "lic_exp": 1782000000,
  "features": { "pro": true },
  "iat": 1759900000,
  "exp": 1759986400,
  "jti": "随机 id"
}
~~~

features 是服务端在签发 license 时设定的任意 JSON,客户端读取它做功能开关与配额。

## 2. 客户端 API

### POST /v1/activate
首次激活:用 license_key 绑定一台设备,返回 access + refresh。

请求体:

~~~json
{
  "license_key": "LIC-....",
  "machine_hash": "设备稳定标识的 SHA256 hex",
  "timestamp": 1759900000,
  "nonce": "随机串 8~128 位,仅限 A-Za-z0-9-_"
}
~~~

响应 200:

~~~json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 86400,
  "access_expires_at": 1759986400,
  "refresh_expires_at": 1762498400,
  "license_expires_at": 1782000000,
  "features": { "pro": true },
  "license_id": "十六进制 id"
}
~~~

### POST /v1/refresh
access 过期前调用,换取新 access(并轮换 refresh,务必覆盖保存)。

请求体:

~~~json
{ "refresh_token": "eyJ...", "timestamp": 1759900000, "nonce": "随机串" }
~~~

响应字段同 activate。

### GET /v1/status
两种用法:
- 推荐:请求头 Authorization: Bearer <access_token> -> 返回 token / license 到期信息(不暴露 license_key)。
- 或:?license_key=...&machine_hash=... -> 返回台账摘要(只读,无需 nonce)。

### GET /v1/pubkey
返回 { "alg": "EdDSA", "pubkey_b64": "...", "pubkey_hex": "..." }。

### GET /healthz
健康检查,返回 { "status": "ok" }。

## 3. 防重放(activate 与 refresh 必做)

- timestamp:Unix 秒,与服务器时间差必须 ≤ 5 分钟(客户端需校时 / 使用服务器时间)。
- nonce:每次请求全新,8~128 位 [A-Za-z0-9-_];服务端内存去重,复用返回 409。

## 4. machine_hash 生成

取设备稳定标识(主板序列号 / 磁盘序列号 / 机器 GUID 等)拼接后做 SHA256,输出小写 hex。
要求同一设备跨重启、重装保持稳定。同一 machine_hash 重复激活是幂等的,不占新席位。

## 5. 客户端状态机(推荐实现)

~~~python
def get_access():
    toks = load()
    if not toks:
        return activate()                      # 首次运行
    if access_valid_locally(toks.access):      # 用公钥验签并检查 exp
        if expiring_soon(toks.access):         # 例如剩余 < 6h
            try: refresh(toks.refresh)         # 后台续期
            except NetworkError: pass          # 断网:凭旧 access 撑到 exp
        return toks.access
    refresh(toks.refresh)                      # access 已过期:必须在线刷新
    return load().access
~~~

要点:

- refresh 返回 401/403 = license 层失效(被吊销 / 过期 / 超席位 / 被踢),应提示用户续费;网络异常则继续用旧 access 直到 exp。
- 每次 refresh 都会返回新的 refresh_token,必须覆盖保存。旧 token 被轮换后立即作废:重用会得到 401(服务端有重用检测),此时应改用最新保存的那枚。
- 公钥随客户端版本发布;服务端轮换密钥时需同步发布新版客户端。

## 6. 错误码

| 状态码 | 含义 |
| --- | --- |
| 400 | 参数错误 / timestamp 超窗 / nonce 格式非法 |
| 401 | Admin Key 或 token 无效 |
| 403 | 已吊销 / 已过期 / 席位已满 / 设备已解绑 |
| 409 | nonce 重放 |

## 7. 管理 API(仅后台运维,严禁打包进客户端)

一律使用请求头 Authorization: Bearer <ADMIN_KEY>。

| 方法 路径 | 说明 |
| --- | --- |
| POST /admin/licenses | 签发,body {"customer","days","seats","features"} |
| GET /admin/licenses | 分页台账,query q/status/page/page_size/sort/order |
| GET /admin/stats | 汇总统计 |
| GET /admin/licenses/{id} | 单个 license + 设备列表 |
| POST /admin/licenses/{id}/revoke | 吊销 |
| POST /admin/licenses/{id}/restore | 恢复 |
| POST /admin/licenses/{id}/extend | 续期,body {"add_days":30} |
| POST /admin/licenses/{id}/update | 修改客户名/席位,body {"customer","seats"} 可只传其一 |
| POST /admin/licenses/{id}/features | 修改功能标记,body {"features":{...}} |
| DELETE /admin/licenses/{id} | 彻底删除(含设备记录) |
| DELETE /admin/licenses/{id}/machines | 解绑全部设备,释放席位 |
| DELETE /admin/licenses/{id}/machines/{mhash} | 踢单台设备,释放席位 |

## 8. 安全

- 生产务必全程 TLS。
- 服务端只存 license_key 的 SHA256;私钥泄露需轮换并重新发布客户端公钥。
- 本系统不做防共享;强绑定场景请用小席位数 + 短 access TTL + 硬件指纹。

