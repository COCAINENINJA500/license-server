// Command license-server 是一个轻量通用云端 License 鉴权服务端.
//
// 特性:
//   - 单二进制、无 CGO (modernc.org/sqlite)、零外部服务依赖,SQLite 本地文件即数据库
//   - 管理 API (Bearer Key 鉴权):签发 / 查询 / 列出 / 吊销 / 恢复 / 续期 / 踢设备
//   - 客户端 API: activate / refresh / status, access JWT(Ed25519, 默认 24h) + refresh JWT(默认 30 天)
//   - 防重放: activate/refresh 必须带 timestamp(±5 分钟) + nonce(内存去重 10 分钟)
//   - 数据模型仅两张表: licenses 与 activations, license_key 只存 SHA256 哈希
//
// 运行:
//
//	go run . --addr :8080 --db licenses.db
//	LICENSE_ADMIN_KEY=xxx go run . --addr :8080
//
// 生产环境请全程 TLS: 直接 --tls-cert/--tls-key,或放在反向代理(Caddy/Nginx)后面.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// 配置与常量
// ---------------------------------------------------------------------------

const (
	// 防重放窗口: timestamp 与服务端时间差允许 ±5 分钟.
	replayWindow = 5 * time.Minute
	// nonce 内存去重保留 10 分钟.
	nonceRetention = 10 * time.Minute

	statusActive  = "active"
	statusRevoked = "revoked"

	issuer = "license-server"

	// expiringWindowSec "即将到期"判定窗口(7 天).
	expiringWindowSec int64 = 7 * 86400
)

const schema = `
CREATE TABLE IF NOT EXISTS licenses (
	id         TEXT PRIMARY KEY,
	key_hash   TEXT UNIQUE NOT NULL,
	customer   TEXT NOT NULL,
	seats      INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	features   TEXT NOT NULL DEFAULT '{}',
	status     TEXT NOT NULL DEFAULT 'active',
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses(key_hash);
CREATE TABLE IF NOT EXISTS activations (
	license_id   TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
	machine_hash TEXT NOT NULL,
	first_seen   INTEGER NOT NULL,
	last_seen    INTEGER NOT NULL,
	PRIMARY KEY (license_id, machine_hash)
);
`

// Config 服务配置(均可由命令行 flag 或环境变量提供).
type Config struct {
	Addr       string
	DBPath     string
	AdminKey   string
	PrivKey    string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	TLSCert    string
	TLSKey     string
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// 防重放: nonce 内存去重
// ---------------------------------------------------------------------------

// NonceStore 记录最近见过的 nonce,防止重放攻击.
type NonceStore struct {
	mu sync.Mutex
	m  map[string]int64 // nonce -> 过期时间 unix 秒
}

func NewNonceStore() *NonceStore { return &NonceStore{m: make(map[string]int64)} }

var nonceFmt = regexp.MustCompile(`^[A-Za-z0-9\-_]{8,128}$`)

// CheckAndRecord 校验 timestamp 是否在窗口内、nonce 是否未见过,通过则记录.
// 返回 nil 表示通过;返回 *httpError 表示拒绝原因(调用方转为对应 HTTP 状态码).
func (n *NonceStore) CheckAndRecord(ts int64, nonce string, now time.Time) *httpError {
	if !nonceFmt.MatchString(nonce) {
		return badRequest("nonce 格式非法(需 8~128 位字母数字/-/_ )")
	}
	nowUnix := now.Unix()
	diff := nowUnix - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(replayWindow/time.Second) {
		return badRequest("timestamp 超出 ±5 分钟窗口(请校准客户端时钟)")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	// 惰性清理过期条目.
	for k, exp := range n.m {
		if exp < nowUnix {
			delete(n.m, k)
		}
	}
	if exp, ok := n.m[nonce]; ok && exp >= nowUnix {
		return &httpError{Code: http.StatusConflict, Msg: "重放拒绝: nonce 已使用"}
	}
	n.m[nonce] = nowUnix + int64(nonceRetention/time.Second)
	return nil
}

// ---------------------------------------------------------------------------
// 错误与 JSON 辅助
// ---------------------------------------------------------------------------

type httpError struct {
	Code int
	Msg  string
}

func badRequest(msg string) *httpError   { return &httpError{Code: http.StatusBadRequest, Msg: msg} }
func unauthorized(msg string) *httpError { return &httpError{Code: http.StatusUnauthorized, Msg: msg} }
func forbidden(msg string) *httpError    { return &httpError{Code: http.StatusForbidden, Msg: msg} }
func notFound(msg string) *httpError     { return &httpError{Code: http.StatusNotFound, Msg: msg} }
func (e *httpError) Error() string       { return e.Msg }
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, err *httpError) {
	writeJSON(w, err.Code, map[string]string{"error": err.Msg})
}
func writeInternal(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "内部错误"})
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

type Server struct {
	db         *sql.DB
	adminKey   string
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	accessTTL  time.Duration
	refreshTTL time.Duration
	nonces     *NonceStore
	now        func() time.Time // 测试可注入固定时间
}

func (s *Server) nowTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func NewServer(db *sql.DB, adminKey string, priv ed25519.PrivateKey, accessTTL, refreshTTL time.Duration) *Server {
	return &Server{
		db:         db,
		adminKey:   adminKey,
		priv:       priv,
		pub:        priv.Public().(ed25519.PublicKey),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		nonces:     NewNonceStore(),
	}
}

func initDB(db *sql.DB) error {
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		return err
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=ON;`); err != nil {
		return err
	}
	_, err := db.Exec(schema)
	return err
}

// ---------------------------------------------------------------------------
// 密钥与哈希工具
// ---------------------------------------------------------------------------

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// loadOrCreateKey 加载 Ed25519 私钥文件,不存在则生成.
// 文件内容为 hex(seed 32 字节 或私钥 64 字节),权限 0600.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		raw := strings.TrimSpace(string(data))
		b, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("私钥文件解析失败(应为 hex): %w", err)
		}
		switch len(b) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(b), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(b), nil
		default:
			return nil, fmt.Errorf("私钥文件长度非法: %d 字节", len(b))
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := priv.Seed()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		return nil, err
	}
	log.Printf("已生成新的 Ed25519 签名密钥: %s", path)
	log.Printf("公钥(随客户端发布, base64): %s", base64.StdEncoding.EncodeToString(pub))
	return priv, nil
}

func generateAdminKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// JWT 签发与校验(Ed25519 / EdDSA)
// ---------------------------------------------------------------------------

func (s *Server) signAccess(licenseID, machineHash string, features json.RawMessage, licenseExp int64) (token string, exp int64, err error) {
	now := s.nowTime()
	exp = now.Add(s.accessTTL).Unix()
	if licenseExp < exp {
		exp = licenseExp // access 有效期不超过 license 到期时间
	}
	var feat any = map[string]any{}
	if len(features) > 0 {
		_ = json.Unmarshal(features, &feat)
	}
	jti, _ := randomHex(8)
	claims := jwt.MapClaims{
		"iss":      issuer,
		"typ":      "access",
		"sub":      licenseID,
		"mhash":    machineHash,
		"lic_exp":  licenseExp,
		"features": feat,
		"iat":      now.Unix(),
		"exp":      exp,
		"jti":      jti,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token, err = t.SignedString(s.priv)
	return token, exp, err
}

func (s *Server) signRefresh(licenseID, machineHash string) (string, int64, error) {
	now := s.nowTime()
	exp := now.Add(s.refreshTTL).Unix()
	jti, _ := randomHex(8)
	claims := jwt.MapClaims{
		"iss":   issuer,
		"typ":   "refresh",
		"sub":   licenseID,
		"mhash": machineHash,
		"iat":   now.Unix(),
		"exp":   exp,
		"jti":   jti,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token, err := t.SignedString(s.priv)
	return token, exp, err
}

func (s *Server) parseToken(token string) (jwt.MapClaims, *httpError) {
	claims := jwt.MapClaims{}
	opt := jwt.WithTimeFunc(func() time.Time { return s.nowTime() })
	t, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("签名算法不符")
		}
		return s.pub, nil
	}, opt)
	if err != nil || !t.Valid {
		return nil, unauthorized("token 无效或已过期")
	}
	return claims, nil
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// ---------------------------------------------------------------------------
// 数据模型
// ---------------------------------------------------------------------------

type licenseRow struct {
	ID        string `json:"license_id"`
	KeyHash   string `json:"-"`
	Customer  string `json:"customer"`
	Seats     int    `json:"seats"`
	ExpiresAt int64  `json:"expires_at"`
	Features  string `json:"-"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Server) getLicenseByHash(hash string) (*licenseRow, error) {
	var l licenseRow
	err := s.db.QueryRow(`SELECT id,key_hash,customer,seats,expires_at,features,status,created_at FROM licenses WHERE key_hash=?`, hash).
		Scan(&l.ID, &l.KeyHash, &l.Customer, &l.Seats, &l.ExpiresAt, &l.Features, &l.Status, &l.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &l, err
}

func (s *Server) getLicenseByID(id string) (*licenseRow, error) {
	var l licenseRow
	err := s.db.QueryRow(`SELECT id,key_hash,customer,seats,expires_at,features,status,created_at FROM licenses WHERE id=?`, id).
		Scan(&l.ID, &l.KeyHash, &l.Customer, &l.Seats, &l.ExpiresAt, &l.Features, &l.Status, &l.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &l, err
}

func (s *Server) countActivations(licenseID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM activations WHERE license_id=?`, licenseID).Scan(&n)
	return n, err
}

// checkUsable 吊销与续费的统一卡点:状态必须 active 且未过期.
func checkUsable(l *licenseRow, nowUnix int64) *httpError {
	if l.Status != statusActive {
		return forbidden("license 已吊销")
	}
	if nowUnix >= l.ExpiresAt {
		return forbidden("license 已过期")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 管理 API (Bearer Key 鉴权)
// ---------------------------------------------------------------------------

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := bearerToken(r)
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.adminKey)) != 1 {
			writeErr(w, unauthorized("管理鉴权失败"))
			return
		}
		next(w, r)
	}
}

type issueReq struct {
	Customer string          `json:"customer"`
	Days     int             `json:"days"`
	Seats    int             `json:"seats"`
	Features json.RawMessage `json:"features"`
}

// POST /admin/licenses 签发 license. license_key 明文仅此一次返回.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req issueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, badRequest("请求体不是合法 JSON"))
		return
	}
	req.Customer = strings.TrimSpace(req.Customer)
	if req.Customer == "" || len(req.Customer) > 128 {
		writeErr(w, badRequest("customer 必填且不超过 128 字符"))
		return
	}
	if req.Days < 1 || req.Days > 3650 {
		writeErr(w, badRequest("days 取值范围 1~3650"))
		return
	}
	if req.Seats < 1 || req.Seats > 100000 {
		writeErr(w, badRequest("seats 取值范围 1~100000"))
		return
	}
	features := "{}"
	if len(req.Features) > 0 {
		var v any
		if err := json.Unmarshal(req.Features, &v); err != nil {
			writeErr(w, badRequest("features 必须是合法 JSON"))
			return
		}
		features = string(req.Features)
	}

	nowUnix := s.nowTime().Unix()
	for tries := 0; tries < 3; tries++ {
		id, err := randomHex(8)
		if err != nil {
			writeInternal(w, err)
			return
		}
		keyBytes := make([]byte, 24)
		if _, err := rand.Read(keyBytes); err != nil {
			writeInternal(w, err)
			return
		}
		key := "LIC-" + hex.EncodeToString(keyBytes)
		expiresAt := nowUnix + int64(req.Days)*86400
		_, err = s.db.Exec(`INSERT INTO licenses(id,key_hash,customer,seats,expires_at,features,status,created_at) VALUES(?,?,?,?,?,?,?,?)`,
			id, sha256Hex(key), req.Customer, req.Seats, expiresAt, features, statusActive, nowUnix)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				continue // 极小概率碰撞,重试
			}
			writeInternal(w, err)
			return
		}
		log.Printf("签发 license: id=%s customer=%s seats=%d days=%d", id, req.Customer, req.Seats, req.Days)
		writeJSON(w, http.StatusCreated, map[string]any{
			"license_id":  id,
			"license_key": key, // 明文仅返回一次,服务端只存哈希
			"customer":    req.Customer,
			"seats":       req.Seats,
			"expires_at":  expiresAt,
			"features":    json.RawMessage(features),
			"status":      statusActive,
		})
		return
	}
	writeInternal(w, fmt.Errorf("license id 碰撞重试耗尽"))
}

type licenseView struct {
	LicenseID string          `json:"license_id"`
	Customer  string          `json:"customer"`
	Seats     int             `json:"seats"`
	Used      int             `json:"used"`
	ExpiresAt int64           `json:"expires_at"`
	Status    string          `json:"status"`
	Features  json.RawMessage `json:"features"`
	CreatedAt int64           `json:"created_at"`
}

func (s *Server) toView(l *licenseRow) (*licenseView, error) {
	used, err := s.countActivations(l.ID)
	if err != nil {
		return nil, err
	}
	feat := l.Features
	if feat == "" {
		feat = "{}"
	}
	return &licenseView{
		LicenseID: l.ID, Customer: l.Customer, Seats: l.Seats, Used: used,
		ExpiresAt: l.ExpiresAt, Status: l.Status,
		Features: json.RawMessage(feat), CreatedAt: l.CreatedAt,
	}, nil
}

// sortColumns 台账可排序字段白名单(键来自前端,值拼进 SQL,故必须白名单).
var sortColumns = map[string]string{
	"customer":   "l.customer",
	"license_id": "l.id",
	"seats":      "l.seats",
	"expires_at": "l.expires_at",
	"status":     "l.status",
	"created_at": "l.created_at",
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

// GET /admin/licenses?q=&status=&page=&page_size=&sort=&order= 分页列出台账.
// 席位占用用子查询一次取回,避免 N+1 与 MaxOpenConns(1) 下的往返.
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	q := strings.TrimSpace(query.Get("q"))
	status := strings.TrimSpace(query.Get("status"))

	page := atoiDefault(query.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	pageSize := atoiDefault(query.Get("page_size"), 20)
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	col, ok := sortColumns[query.Get("sort")]
	if !ok {
		col = "l.created_at"
	}
	dir := "DESC"
	if strings.EqualFold(query.Get("order"), "asc") {
		dir = "ASC"
	}

	now := s.nowTime().Unix()
	where := []string{"1=1"}
	args := []any{}
	if q != "" {
		where = append(where, "(l.customer LIKE ? OR l.id LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like)
	}
	switch status {
	case statusRevoked:
		where = append(where, "l.status=?")
		args = append(args, statusRevoked)
	case "expired":
		where = append(where, "l.status=? AND l.expires_at<=?")
		args = append(args, statusActive, now)
	case "expiring":
		where = append(where, "l.status=? AND l.expires_at>? AND l.expires_at<=?")
		args = append(args, statusActive, now, now+expiringWindowSec)
	case "active":
		where = append(where, "l.status=? AND l.expires_at>?")
		args = append(args, statusActive, now)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM licenses l WHERE `+whereSQL, args...).Scan(&total); err != nil {
		writeInternal(w, err)
		return
	}

	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(`SELECT l.id,l.customer,l.seats,l.expires_at,l.features,l.status,l.created_at,
		(SELECT COUNT(*) FROM activations a WHERE a.license_id=l.id)
		FROM licenses l WHERE `+whereSQL+` ORDER BY `+col+` `+dir+` LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		writeInternal(w, err)
		return
	}
	defer rows.Close()
	out := []*licenseView{}
	for rows.Next() {
		var l licenseRow
		var used int
		if err := rows.Scan(&l.ID, &l.Customer, &l.Seats, &l.ExpiresAt, &l.Features, &l.Status, &l.CreatedAt, &used); err != nil {
			writeInternal(w, err)
			return
		}
		feat := l.Features
		if feat == "" {
			feat = "{}"
		}
		out = append(out, &licenseView{
			LicenseID: l.ID, Customer: l.Customer, Seats: l.Seats, Used: used,
			ExpiresAt: l.ExpiresAt, Status: l.Status,
			Features: json.RawMessage(feat), CreatedAt: l.CreatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		writeInternal(w, err)
		return
	}
	totalPages := (total + pageSize - 1) / pageSize
	writeJSON(w, http.StatusOK, map[string]any{
		"licenses": out, "total": total,
		"page": page, "page_size": pageSize, "total_pages": totalPages,
	})
}

// GET /admin/stats 汇总统计(供管理台概览页).
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	now := s.nowTime().Unix()
	var total, revoked, expired, expiring, seats, used int
	err := s.db.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status=? AND expires_at<=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status=? AND expires_at>? AND expires_at<=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(seats),0),
		(SELECT COUNT(*) FROM activations)
		FROM licenses`,
		statusRevoked, statusActive, now, statusActive, now, now+expiringWindowSec).
		Scan(&total, &revoked, &expired, &expiring, &seats, &used)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": total, "active": total - revoked - expired, "expiring": expiring,
		"expired": expired, "revoked": revoked, "seats": seats, "used": used,
	})
}

// GET /admin/licenses/{id} 查询单个台账(含设备列表).
func (s *Server) handleGetOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	l, err := s.getLicenseByID(id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, notFound("license 不存在"))
		return
	}
	v, err := s.toView(l)
	if err != nil {
		writeInternal(w, err)
		return
	}
	machines, err := s.listMachines(id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"license": v, "machines": machines})
}

type machineView struct {
	MachineHash string `json:"machine_hash"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
}

func (s *Server) listMachines(licenseID string) ([]*machineView, error) {
	rows, err := s.db.Query(`SELECT machine_hash,first_seen,last_seen FROM activations WHERE license_id=? ORDER BY first_seen`, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*machineView
	for rows.Next() {
		var m machineView
		if err := rows.Scan(&m.MachineHash, &m.FirstSeen, &m.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, &machineView{MachineHash: m.MachineHash, FirstSeen: m.FirstSeen, LastSeen: m.LastSeen})
	}
	if out == nil {
		out = []*machineView{}
	}
	return out, nil
}

// POST /admin/licenses/{id}/revoke 吊销(下次 refresh 生效,最长延迟 1 个 access 有效期).
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := s.db.Exec(`UPDATE licenses SET status=? WHERE id=?`, statusRevoked, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, notFound("license 不存在"))
		return
	}
	log.Printf("吊销 license: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]string{"license_id": id, "status": statusRevoked})
}

// POST /admin/licenses/{id}/restore 恢复已吊销的 license.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := s.db.Exec(`UPDATE licenses SET status=? WHERE id=?`, statusActive, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, notFound("license 不存在"))
		return
	}
	log.Printf("恢复 license: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]string{"license_id": id, "status": statusActive})
}

// POST /admin/licenses/{id}/extend 续费: body {"add_days": 30}.
func (s *Server) handleExtend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		AddDays int `json:"add_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, badRequest("请求体不是合法 JSON"))
		return
	}
	if req.AddDays < 1 || req.AddDays > 3650 {
		writeErr(w, badRequest("add_days 取值范围 1~3650"))
		return
	}
	l, err := s.getLicenseByID(id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, notFound("license 不存在"))
		return
	}
	base := l.ExpiresAt
	if base < s.nowTime().Unix() {
		base = s.nowTime().Unix() // 已过期的从现在起续
	}
	newExp := base + int64(req.AddDays)*86400
	if _, err := s.db.Exec(`UPDATE licenses SET expires_at=? WHERE id=?`, newExp, id); err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("续期 license: id=%s add_days=%d new_expires_at=%d", id, req.AddDays, newExp)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "expires_at": newExp})
}

// DELETE /admin/licenses/{id} 彻底删除 license 及其全部激活记录(不可恢复).
// 用于清理误签发/测试/已废弃的凭证(含已吊销的),与吊销/恢复那种"保留台账"的语义不同.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tx, err := s.db.Begin()
	if err != nil {
		writeInternal(w, err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM activations WHERE license_id=?`, id); err != nil {
		writeInternal(w, err)
		return
	}
	res, err := tx.Exec(`DELETE FROM licenses WHERE id=?`, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, notFound("license 不存在"))
		return
	}
	if err := tx.Commit(); err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("删除 license: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "deleted": true})
}

// POST /admin/licenses/{id}/update 修改客户名 / 席位数.
// 下调 seats 到低于占用量时,超出部分的设备会在下次 refresh 被拒.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Customer *string `json:"customer"`
		Seats    *int    `json:"seats"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, badRequest("请求体不是合法 JSON"))
		return
	}
	if req.Customer == nil && req.Seats == nil {
		writeErr(w, badRequest("至少提供 customer 或 seats"))
		return
	}
	l, err := s.getLicenseByID(id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, notFound("license 不存在"))
		return
	}
	if req.Customer != nil {
		c := strings.TrimSpace(*req.Customer)
		if c == "" || len(c) > 128 {
			writeErr(w, badRequest("customer 必填且不超过 128 字符"))
			return
		}
		l.Customer = c
	}
	if req.Seats != nil {
		if *req.Seats < 1 || *req.Seats > 100000 {
			writeErr(w, badRequest("seats 取值范围 1~100000"))
			return
		}
		l.Seats = *req.Seats
	}
	if _, err := s.db.Exec(`UPDATE licenses SET customer=?, seats=? WHERE id=?`, l.Customer, l.Seats, id); err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("更新 license: id=%s customer=%s seats=%d", id, l.Customer, l.Seats)
	v, err := s.toView(l)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"license": v})
}

// DELETE /admin/licenses/{id}/machines 解绑该 license 的全部设备(释放席位,下次 refresh 被拒).
func (s *Server) handleUnbindAll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	l, err := s.getLicenseByID(id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, notFound("license 不存在"))
		return
	}
	res, err := s.db.Exec(`DELETE FROM activations WHERE license_id=?`, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	n, _ := res.RowsAffected()
	log.Printf("解绑全部设备: license=%s unbound=%d", id, n)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "unbound": n})
}

// POST /admin/licenses/{id}/features 修改功能标记(客户端下次 refresh 生效).
func (s *Server) handleUpdateFeatures(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Features json.RawMessage `json:"features"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, badRequest("请求体不是合法 JSON"))
		return
	}
	if len(req.Features) == 0 {
		writeErr(w, badRequest("features 必填"))
		return
	}
	var v any
	if err := json.Unmarshal(req.Features, &v); err != nil {
		writeErr(w, badRequest("features 必须是合法 JSON"))
		return
	}
	res, err := s.db.Exec(`UPDATE licenses SET features=? WHERE id=?`, string(req.Features), id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, notFound("license 不存在"))
		return
	}
	log.Printf("更新功能标记: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "features": json.RawMessage(req.Features)})
}

// DELETE /admin/licenses/{id}/machines/{mhash} 踢掉一台设备,释放席位(下次 refresh 生效).
func (s *Server) handleKick(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	mhash := r.PathValue("mhash")
	res, err := s.db.Exec(`DELETE FROM activations WHERE license_id=? AND machine_hash=?`, id, mhash)
	if err != nil {
		writeInternal(w, err)
		return
	}
	n, _ := res.RowsAffected()
	log.Printf("踢设备: license=%s machine=%.12s... deleted=%d", id, mhash, n)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "deleted": n > 0})
}

// ---------------------------------------------------------------------------
// 客户端 API
// ---------------------------------------------------------------------------

type activateReq struct {
	LicenseKey  string `json:"license_key"`
	MachineHash string `json:"machine_hash"`
	Timestamp   int64  `json:"timestamp"`
	Nonce       string `json:"nonce"`
}

// POST /v1/activate 激活设备并下发 access + refresh.
func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	var req activateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, badRequest("请求体不是合法 JSON"))
		return
	}
	if herr := s.nonces.CheckAndRecord(req.Timestamp, req.Nonce, s.nowTime()); herr != nil {
		writeErr(w, herr)
		return
	}
	req.LicenseKey = strings.TrimSpace(req.LicenseKey)
	req.MachineHash = strings.TrimSpace(req.MachineHash)
	if req.LicenseKey == "" || req.MachineHash == "" || len(req.MachineHash) > 128 {
		writeErr(w, badRequest("license_key 与 machine_hash 必填(machine_hash 建议为设备标识的 SHA256 hex)"))
		return
	}
	l, err := s.getLicenseByHash(sha256Hex(req.LicenseKey))
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, unauthorized("license_key 无效"))
		return
	}
	nowUnix := s.nowTime().Unix()
	if herr := checkUsable(l, nowUnix); herr != nil {
		writeErr(w, herr)
		return
	}
	// 席位控制: 同一 machine 重复激活幂等,不占新席位.
	var exists bool
	err = s.db.QueryRow(`SELECT 1 FROM activations WHERE license_id=? AND machine_hash=?`, l.ID, req.MachineHash).Scan(new(int))
	switch err {
	case nil:
		exists = true
	case sql.ErrNoRows:
		exists = false
	default:
		writeInternal(w, err)
		return
	}
	if exists {
		if _, err := s.db.Exec(`UPDATE activations SET last_seen=? WHERE license_id=? AND machine_hash=?`, nowUnix, l.ID, req.MachineHash); err != nil {
			writeInternal(w, err)
			return
		}
	} else {
		used, err := s.countActivations(l.ID)
		if err != nil {
			writeInternal(w, err)
			return
		}
		if used >= l.Seats {
			writeErr(w, forbidden("席位已满"))
			return
		}
		if _, err := s.db.Exec(`INSERT INTO activations(license_id,machine_hash,first_seen,last_seen) VALUES(?,?,?,?)`, l.ID, req.MachineHash, nowUnix, nowUnix); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY") {
				writeErr(w, forbidden("席位已满"))
				return
			}
			writeInternal(w, err)
			return
		}
	}
	access, accessExp, err := s.signAccess(l.ID, req.MachineHash, json.RawMessage(l.Features), l.ExpiresAt)
	if err != nil {
		writeInternal(w, err)
		return
	}
	refresh, refreshExp, err := s.signRefresh(l.ID, req.MachineHash)
	if err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("激活: license=%.8s machine=%.12s...", l.ID, req.MachineHash)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       access,
		"refresh_token":      refresh,
		"expires_in":         accessExp - nowUnix,
		"access_expires_at":  accessExp,
		"refresh_expires_at": refreshExp,
		"license_expires_at": l.ExpiresAt,
		"features":           json.RawMessage(l.Features),
		"license_id":         l.ID,
	})
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
}

// POST /v1/refresh 用 refresh 换新 access.
// 吊销 / 过期 / 超席位 / 被踢均在此拒绝 —— 这是吊销与续费的唯一卡点.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, badRequest("请求体不是合法 JSON"))
		return
	}
	if herr := s.nonces.CheckAndRecord(req.Timestamp, req.Nonce, s.nowTime()); herr != nil {
		writeErr(w, herr)
		return
	}
	if req.RefreshToken == "" {
		writeErr(w, badRequest("refresh_token 必填"))
		return
	}
	claims, herr := s.parseToken(req.RefreshToken)
	if herr != nil {
		writeErr(w, herr)
		return
	}
	if claims["typ"] != "refresh" {
		writeErr(w, unauthorized("不是合法的 refresh token"))
		return
	}
	lid, _ := claims["sub"].(string)
	mhash, _ := claims["mhash"].(string)
	if lid == "" || mhash == "" {
		writeErr(w, unauthorized("refresh token 内容非法"))
		return
	}
	l, err := s.getLicenseByID(lid)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, forbidden("license 不存在或已吊销"))
		return
	}
	nowUnix := s.nowTime().Unix()
	if herr := checkUsable(l, nowUnix); herr != nil {
		writeErr(w, herr) // 吊销 / 过期在此拒绝
		return
	}
	// 被踢检查: 设备行不在即拒绝.
	var one int
	if err := s.db.QueryRow(`SELECT 1 FROM activations WHERE license_id=? AND machine_hash=?`, lid, mhash).Scan(&one); err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, forbidden("设备已被解绑"))
			return
		}
		writeInternal(w, err)
		return
	}
	// 超席位检查(如管理员下调 seats):总数超限即拒绝.
	used, err := s.countActivations(lid)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if used > l.Seats {
		writeErr(w, forbidden("席位已满(管理员下调了席位数)"))
		return
	}
	if _, err := s.db.Exec(`UPDATE activations SET last_seen=? WHERE license_id=? AND machine_hash=?`, nowUnix, lid, mhash); err != nil {
		writeInternal(w, err)
		return
	}
	access, accessExp, err := s.signAccess(l.ID, mhash, json.RawMessage(l.Features), l.ExpiresAt)
	if err != nil {
		writeInternal(w, err)
		return
	}
	// 轮换 refresh: 每次 refresh 同时下发新的 refresh token.
	newRefresh, refreshExp, err := s.signRefresh(l.ID, mhash)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       access,
		"refresh_token":      newRefresh,
		"expires_in":         accessExp - nowUnix,
		"access_expires_at":  accessExp,
		"refresh_expires_at": refreshExp,
		"license_expires_at": l.ExpiresAt,
		"features":           json.RawMessage(l.Features),
		"license_id":         l.ID,
	})
}

// GET /v1/status 查询剩余有效期.
// 两种用法:
//  1. Authorization: Bearer <access_token> -> 返回 token/ license 到期信息(推荐,不暴露 license_key)
//  2. ?license_key=...&machine_hash=...   -> 返回台账摘要(只读,无需 nonce)
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if tok := bearerToken(r); tok != "" {
		claims, herr := s.parseToken(tok)
		if herr != nil {
			writeErr(w, herr)
			return
		}
		expF, _ := claims["exp"].(float64)
		licExpF, _ := claims["lic_exp"].(float64)
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":              true,
			"license_id":         claims["sub"],
			"machine_hash":       claims["mhash"],
			"token_expires_at":   int64(expF),
			"license_expires_at": int64(licExpF),
			"features":           claims["features"],
		})
		return
	}
	key := strings.TrimSpace(r.URL.Query().Get("license_key"))
	mhash := strings.TrimSpace(r.URL.Query().Get("machine_hash"))
	if key == "" {
		writeErr(w, badRequest("缺少 license_key(或改用 Authorization: Bearer <access_token>)"))
		return
	}
	l, err := s.getLicenseByHash(sha256Hex(key))
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, unauthorized("license_key 无效"))
		return
	}
	used, err := s.countActivations(l.ID)
	if err != nil {
		writeInternal(w, err)
		return
	}
	nowUnix := s.nowTime().Unix()
	valid := l.Status == statusActive && nowUnix < l.ExpiresAt
	bound := false
	if mhash != "" {
		var one int
		if err := s.db.QueryRow(`SELECT 1 FROM activations WHERE license_id=? AND machine_hash=?`, l.ID, mhash).Scan(&one); err == nil {
			bound = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":             valid,
		"license_id":        l.ID,
		"status":            l.Status,
		"expires_at":        l.ExpiresAt,
		"remaining_seconds": max(l.ExpiresAt-nowUnix, 0),
		"seats":             l.Seats,
		"used":              used,
		"bound":             bound,
		"features":          json.RawMessage(l.Features),
	})
}

// GET /v1/pubkey 返回 Ed25519 公钥(方便客户端抓取嵌入发布).
func (s *Server) handlePubkey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"alg":        "EdDSA",
		"pubkey_b64": base64.StdEncoding.EncodeToString(s.pub),
		"pubkey_hex": hex.EncodeToString(s.pub),
	})
}

// ---------------------------------------------------------------------------
// 路由与启动
// ---------------------------------------------------------------------------

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/pubkey", s.handlePubkey)
	mux.HandleFunc("POST /v1/activate", s.handleActivate)
	mux.HandleFunc("POST /v1/refresh", s.handleRefresh)
	mux.HandleFunc("GET /v1/status", s.handleStatus)

	// 内嵌单租户管理台(无鉴权页面本身,调 API 时用 Admin Key).
	mux.HandleFunc("GET /admin", s.handleAdminUI)
	mux.HandleFunc("GET /admin/", s.handleAdminUI)
	// 实时生成的对接文档(下载给其他 Coding Agent).
	mux.HandleFunc("GET /admin/integration.md", s.requireAdmin(s.handleIntegrationDoc))

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
	return withCORS(withLogging(mux))
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

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

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Addr, "addr", envOr("LICENSE_ADDR", ":8080"), "监听地址")
	flag.StringVar(&cfg.DBPath, "db", envOr("LICENSE_DB", "licenses.db"), "SQLite 文件路径")
	flag.StringVar(&cfg.AdminKey, "admin-key", envOr("LICENSE_ADMIN_KEY", ""), "管理 API 的 Bearer Key(为空则自动生成并打印)")
	flag.StringVar(&cfg.PrivKey, "privkey", envOr("LICENSE_PRIVKEY", "license_ed25519.key"), "Ed25519 私钥文件(hex seed)")
	defAccess, _ := time.ParseDuration(envOr("LICENSE_ACCESS_TTL", "24h"))
	if defAccess <= 0 {
		defAccess = 24 * time.Hour
	}
	defRefresh, _ := time.ParseDuration(envOr("LICENSE_REFRESH_TTL", "720h"))
	if defRefresh <= 0 {
		defRefresh = 30 * 24 * time.Hour
	}
	flag.DurationVar(&cfg.AccessTTL, "access-ttl", defAccess, "access JWT 有效期(离线宽限上限,可配)")
	flag.DurationVar(&cfg.RefreshTTL, "refresh-ttl", defRefresh, "refresh token 有效期")
	flag.StringVar(&cfg.TLSCert, "tls-cert", envOr("LICENSE_TLS_CERT", ""), "TLS 证书文件(为空则明文 HTTP,生产请配置)")
	flag.StringVar(&cfg.TLSKey, "tls-key", envOr("LICENSE_TLS_KEY", ""), "TLS 私钥文件")
	flag.Parse()

	priv, err := loadOrCreateKey(cfg.PrivKey)
	if err != nil {
		log.Fatalf("加载签名密钥失败: %v", err)
	}
	if cfg.AdminKey == "" {
		gen, err := generateAdminKey()
		if err != nil {
			log.Fatalf("生成 admin key 失败: %v", err)
		}
		cfg.AdminKey = gen
		log.Printf("注意: 未配置管理 Key,已自动生成(重启会变,生产请设置 LICENSE_ADMIN_KEY): %s", gen)
	}

	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := initDB(db); err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	srv := NewServer(db, cfg.AdminKey, priv, cfg.AccessTTL, cfg.RefreshTTL)
	log.Printf("license-server 启动: addr=%s db=%s access_ttl=%s refresh_ttl=%s", cfg.Addr, cfg.DBPath, cfg.AccessTTL, cfg.RefreshTTL)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("TLS 已启用(全程加密)")
		log.Fatal(http.ListenAndServeTLS(cfg.Addr, cfg.TLSCert, cfg.TLSKey, srv.routes()))
	}
	log.Printf("警告: 当前为明文 HTTP,仅用于本地开发;生产请配置 --tls-cert/--tls-key 或放在反向代理后启用 HTTPS")
	log.Fatal(http.ListenAndServe(cfg.Addr, srv.routes()))
}
